"use client";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import React, { FormEvent, useState } from "react";
import Swal from "sweetalert2";

const LoginForm = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);

    // Validación básica
    if (!email || !password) {
      Swal.fire({
        icon: "error",
        title: "Campos requeridos",
        text: "Por favor complete todos los campos",
      });
      setIsLoading(false);
      return;
    }

    try {
      const res = await signIn("credentials", {
        email,
        password,
        redirect: false,
      });

      console.log("Resultado de signIn:", res); // Agregado para depuración

      if (res?.ok) {
        await Swal.fire({
          icon: "success",
          title: "¡Bienvenido!",
          text: "Inicio de sesión exitoso",
          timer: 1500,
          showConfirmButton: false,
        });
        router.push("/home");
      } else {
        Swal.fire({
          icon: "error",
          title: "Error",
          text: res?.error || "Credenciales incorrectas",
        });
      }
    } catch (error) {
      console.error(error);
      Swal.fire({
        icon: "error",
        title: "Error",
        text: "Ocurrió un error inesperado",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-4xl bg-gray-800 rounded-xl shadow-2xl overflow-hidden border border-gray-700">
        <div className="flex flex-col md:flex-row">
          {/* Sección de imagen */}
          <div className="hidden md:flex md:w-1/2 bg-gradient-to-br from-blue-600 to-blue-800 items-center justify-center p-12">
            <div className="text-center">
              <div
                className="w-full h-64 bg-contain bg-center bg-no-repeat opacity-90"
                style={{
                  backgroundImage: `url(login.svg)`,
                }}
              />
              <h2 className="text-3xl font-bold text-white mt-8">
                Bienvenido de vuelta
              </h2>
            </div>
          </div>

          {/* Sección del formulario */}
          <div className="w-full md:w-1/2 py-10 px-6 sm:px-12">
            <div className="text-center mb-10">
              <h1 className="text-3xl font-bold text-white">Iniciar Sesión</h1>
              <p className="text-gray-400 mt-2">
                Ingresa tu correo y contraseña
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none"></div>
                <input
                  className="w-full pl-10 pr-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  type="email"
                  name="email"
                  placeholder="Correo electrónico"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none"></div>
                <input
                  className="w-full pl-10 pr-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  type="password"
                  name="password"
                  placeholder="Contraseña"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <button
                type="submit"
                className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-lg font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-300 disabled:opacity-70 disabled:cursor-not-allowed"
                disabled={isLoading}
              >
                {isLoading ? <>Procesando...</> : "Iniciar Sesión"}
              </button>
            </form>

            <div className="mt-8 text-center">
              <p className="text-gray-400">
                ¿No tienes una cuenta?{" "}
                <a
                  href="/register"
                  className="text-blue-500 hover:text-blue-400 font-medium"
                >
                  Regístrate
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginForm;
