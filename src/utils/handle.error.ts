import { Prisma } from '@prisma/client';

import { z } from "zod";

const throwError = (error: any) => {
  console.error("Error:", error);

  // Penanganan error dari token otentikasi
  if (error.code === "auth/id-token-expired") {
    throw {
      status: 401,
      message: "Invalid or expired token",
    };
  }

  // Penanganan error validasi dengan Zod
  if (error instanceof z.ZodError) {
    throw {
      status: 400,
      message: "Validation error: Invalid input",
      errors: error.errors.map((err) => ({
        fieldName: err.path[0] || "unknown", 
        required: err.code === "invalid_type" && err.received === "undefined", 
      })),
    };
  }

  // Penanganan error Prisma yang dikenal
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    switch (error.code) {
      case "P2002":
        const target = error.meta?.target || "field";
        throw {
          status: 409,
          message: `Conflict: The ${target} value must be unique. Try another one.`,
        };
      case "P2025":
        throw {
          status: 404,
          message: "Resource not found.",
        };
      case "P2003":
        throw {
          status: 400,
          message: "Foreign key constraint failed. Please check related data.",
        };
      case "P2000":
        throw {
          status: 400,
          message: `Input value is too long for the field. Adjust your data and try again.`,
        };
      case "P2014":
        throw {
          status: 400,
          message: "Multiple cascade paths detected, which could lead to inconsistent data.",
        };
      default:
        throw {
          status: 500,
          message: `Prisma error (${error.code}): ${error.message}`,
        };
    }
  }

  // Penanganan error Prisma terkait koneksi database
  if (error instanceof Prisma.PrismaClientInitializationError) {
    throw {
      status: 500,
      message: "Database connection error. Please ensure your database is online.",
    };
  }

  if (error instanceof Prisma.PrismaClientRustPanicError) {
    throw {
      status: 500,
      message: "A critical error occurred in Prisma's query engine.",
    };
  }

  if (error instanceof Prisma.PrismaClientValidationError) {
    throw {
      status: 400,
      message: "Validation error: Please check your data.",
    };
  }

  if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    throw {
      status: 500,
      message: "An unknown error occurred in the Prisma query engine.",
    };
  }

  // Penanganan error umum
  if (error instanceof Error) {
    switch (error.name) {
      case "P1013":
        throw {
          status: 500,
          message: "Database connection timeout. Please try again later.",
        };
      case "P3001":
        throw {
          status: 500,
          message: "Database is in an offline mode. Please check your connection.",
        };
      default:
        throw {
          status: 500,
          message: `An unexpected error occurred: ${error.message}`,
        };
    }
  }

  // Penanganan default jika error tidak dikenali
  throw {
    status: 400,
    message: "An unexpected error occurred. Please contact support if this continues.",
  };
};

export default throwError;
