"use client";
import axios, { AxiosError } from "axios";
import { useRouter } from "next/navigation";
import React, { FormEvent, useState } from "react";
import Swal from "sweetalert2";

const RegistrationForm = () => {
  const [role, setRole] = useState("TeamMember");
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);

    const formData = new FormData(e.currentTarget);
    const data = {
      email: formData.get("email"),
      password: formData.get("password"),
      fullname: formData.get("fullname"),
      role: formData.get("role"),
    };

    // Validación básica
    if (!data.email || !data.password || !data.fullname) {
      Swal.fire({
        icon: "error",
        title: "Campos requeridos",
        text: "Por favor complete todos los campos obligatorios",
      });
      setIsLoading(false);
      return;
    }

    try {
      const signupResponse = await axios.post("/api/auth/signup", data);

      await Swal.fire({
        icon: "success",
        title: "¡Registro exitoso!",
        text: signupResponse.data.message,
        timer: 1500,
        showConfirmButton: false,
      });

      router.push("/dashboard");
    } catch (error) {
      console.error(error);
      if (error instanceof AxiosError) {
        Swal.fire({
          icon: "error",
          title: "Error",
          text:
            error.response?.data.message ||
            "Ocurrió un error durante el registro",
        });
      } else {
        Swal.fire({
          icon: "error",
          title: "Error",
          text: "Ocurrió un error inesperado",
        });
      }
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
                style={{ backgroundImage: `url(login.svg)` }}
              />
              <h2 className="text-3xl font-bold text-white mt-8">
                Crear nueva cuenta
              </h2>
            </div>
          </div>

          {/* Sección del formulario */}
          <div className="w-full md:w-1/2 py-10 px-6 sm:px-12">
            <div className="text-center mb-10">
              <h1 className="text-3xl font-bold text-white">
                Registro de Usuario
              </h1>
              <p className="text-gray-400 mt-2">
                Ingresa los campos del nuevo usuario
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="relative">
                <input
                  className="w-full pl-10 pr-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  type="text"
                  name="fullname"
                  placeholder="Nombre completo"
                  required
                  disabled={isLoading}
                />
              </div>

              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none"></div>
                <input
                  className="w-full pl-10 pr-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  type="email"
                  name="email"
                  placeholder="Correo electrónico"
                  required
                  disabled={isLoading}
                />
              </div>

              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <span className="text-gray-400"></span>
                </div>
                <select
                  className="w-full pl-10 pr-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent appearance-none"
                  value={role}
                  name="role"
                  onChange={(e) => setRole(e.target.value)}
                  disabled={isLoading}
                >
                  <option value="TeamMember">Miembro del Equipo</option>
                  <option value="ProjectManager">Gerente de Proyecto</option>
                  <option value="Admin">Administrador</option>
                </select>
              </div>

              <div className="relative">
                <input
                  className="w-full pl-10 pr-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  type="password"
                  name="password"
                  placeholder="Contraseña"
                  required
                  disabled={isLoading}
                />
              </div>

              <button
                type="submit"
                className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-lg font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-300 disabled:opacity-70 disabled:cursor-not-allowed"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <span className="animate-spin mr-2">🌀</span>
                    Registrando...
                  </>
                ) : (
                  "Registrar Usuario"
                )}
              </button>
            </form>

            <div className="mt-8 text-center">
              <p className="text-gray-400">
                ¿Ya tienes una cuenta?{" "}
                <a
                  href="/login"
                  className="text-blue-500 hover:text-blue-400 font-medium"
                >
                  Iniciar Sesión
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RegistrationForm;
