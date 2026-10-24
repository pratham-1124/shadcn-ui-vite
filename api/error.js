import { sendTelemetry } from './_telemetry.js';

export default async function handler(req, res) {
  try {
    // Intentional server error for verification
    console.error("Test Error: Intentional runtime crash on Vercel");
    throw new Error("Temporary runtime error generated for log verification");
  } catch (error) {
    try {
      const vercelId = req?.headers?.['x-vercel-id'] || req?.headers?.['x-request-id'];
      const requestId = typeof vercelId === 'string' ? vercelId : (Array.isArray(vercelId) ? vercelId[0] : undefined);
      const path = (req?.url || '/api/error').split('?')[0];

      await sendTelemetry({
        ...(requestId && { id: `evt_${requestId}`, requestId }),
        message: error.message,
        level: 'ERROR',
        source: 'runtime',
        path,
        statusCode: 500,
      });
    } catch {
      // Telemetry failures must never prevent returning the 500 response
    }

    // Preserve existing response behavior (500 Internal Server Error)
    res.status(500).json({
      error: "Internal Server Error",
      message: error.message,
    });
  }
}
