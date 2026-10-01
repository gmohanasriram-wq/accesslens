import { NextRequest, NextResponse } from "next/server";

const BASE_URL = process.env.API_BASE_URL ?? "http://127.0.0.1:8000";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const searchParams = request.nextUrl.searchParams;
  const q = searchParams.get("q");
  const history = searchParams.get("history");

  const targetUrl = new URL(
    `${BASE_URL}/api/analysis/findings/${encodeURIComponent(id)}/investigation`,
  );
  if (q) targetUrl.searchParams.set("q", q);
  if (history) targetUrl.searchParams.set("history", history);

  try {
    const res = await fetch(targetUrl.toString(), {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      cache: "no-store",
    });

    const text = await res.text();
    let data: unknown;
    try {
      data = JSON.parse(text);
      return NextResponse.json(data, { status: res.status });
    } catch {
      return new NextResponse(text, {
        status: res.status,
        headers: { "Content-Type": "application/json" },
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      {
        detail: `Analysis backend service is unreachable (${message}). Ensure the backend is running on ${BASE_URL}.`,
      },
      { status: 503 },
    );
  }
}
