import { reportError } from './_telemetry.js';

export default async function handler(req, res) {
  try {
    // Intentional server error for verification
    console.error("Test Error: Intentional runtime crash on Vercel");
    throw new Error("Temporary runtime error generated for log verification");
  } catch (error) {
    // Asynchronously report observed application error to NexusMind
    await reportError(error, req);

    // Preserve existing response behavior (500 Internal Server Error)
    res.status(500).json({
      error: "Internal Server Error",
      message: error.message,
    });
  }
}
