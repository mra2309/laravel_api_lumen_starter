<?php

namespace App\Http\Controllers;

use App\Models\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    //

    public function register(Request $request)
    {
        $validate = $this->validate($request,[
            'name'      => 'required|max:255',
            'email'     => 'required|email|max:255|unique:users,email',
            'password'  => 'required'
        ]);

        $user = new User();
        $user->name = $validate['name'];
        $user->email = $validate['email'];
        $user->password = Hash::make($validate['password']);
        $user->save();


        return response()->json($user,201);
    }


    public function login(Request $request)
    {
        $validate = $this->validate($request,[
            'email'     => "required|exists:users,email",
            'password'  => "required"
        ]);

        $user = User::where('email', $validate['email'])->first();

        if(!Hash::check($validate['password'],$user->password)){
            return abort(401,"email or password invalid");
        }else{
            $payload = [
                'nbf' => intval(microtime(true)),
                'iat' => intval(microtime(true)) + (60 * 60 * 1000),
                'uid' => $user->id
            ];

            $token = JWT::encode($payload,env('JWT_SECRET'),'HS256');

            return response()->json(['access_token' => $token ]);
        }
    }
}
