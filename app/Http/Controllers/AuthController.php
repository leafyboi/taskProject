<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'email' => 'email|required'|'unique:users',
            'name' => ['required', 'max:25', 'regex:/[А-Яа-яЁё]/u'],
            'password' => 'required|confirmed|min:6'
        ]);

        $validatedData['password'] = bcrypt($request->password);

        $user = User::create($validatedData);

        if ($user) {
            return response()->json([
                'message' => 'Регистрация прошла успешно. Вы были перенаправлены на страницу авторизации.'
            ], 201);
        }
    }

    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'email|required',
            'password' => 'required'
        ]);

        if (!auth()->attempt($loginData)) {
            return response([
                'message' => 'Неверный пароль или адрес электронной почты.'
            ], 404);
        }

        $user = Auth::user();

        $token = $user->generateToken(); // accessTok
        $user->api_token = $token;

        Auth::user()->save();

        return response([
            'user' => auth()->user(),
            'token' => $token,
        ]);
    }

    public function logout()
    {
        auth()->logout();

        return response()->json([
            'message' => 'Вы успешно вышли из системы.'
        ], 201);
    }
}
