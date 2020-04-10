<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Traits\PassportToken;
use App\User;

class AuthController extends Controller
{
    use PassportToken;

    public function loginByGoogle(Request $request)
    {   

        $curl_handle = curl_init();
        curl_setopt($curl_handle, CURLOPT_URL, 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=' . $request->token);
        curl_setopt($curl_handle, CURLOPT_CONNECTTIMEOUT, 0);
        curl_setopt($curl_handle, CURLOPT_RETURNTRANSFER, 1);
        $response = json_decode(curl_exec($curl_handle));
        curl_close($curl_handle);
        if (!isset($response->email)) {
            return response()->json(['error' => 'wrong google token / this google token is already expired.'], 401);
        }

        // we get feedback from google & can use this email for creating a new user
        // then pass it to Laravel passport
        $user = User::where('email', $response->email)->first();
        if (!$user) {
            $user = new User();
            $user->name = $response->email;
            $user->email = $response->email;
            $user->password = bcrypt('PUT_RANDOM_PASSWORD_HERE_IF_YOU_WISH');
            $user->save();            
        }        

        //this traits PassportToken comes in handy
        //you don't need to generate token with password
        $token = $this->getBearerTokenByUser($user);
        return response()->json(['data' => $token], 200);

    }
    
}
