export default function handler(req, res) {
  // Small intentional server error
  console.error("Test Error: Intentional runtime crash on Vercel");
  throw new Error("Temporary runtime error generated for log verification");
}
