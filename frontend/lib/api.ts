/**
 * Typed client for the AccessLens backend.
 *
 * Server-side only. The base URL is read from `API_BASE_URL` without the
 * `NEXT_PUBLIC_` prefix, so it is never inlined into the client bundle and the
 * browser never talks to the backend directly. That is deliberate for Phase 1 —
 * the API is an internal service, and keeping it server-side means there is no
 * CORS surface and no backend address exposed to a reviewer's browser.
 */

import type { HealthResponse, PersonaListResponse } from "@/types/api";

const BASE_URL = process.env.API_BASE_URL ?? "http://127.0.0.1:8000";

/** An error carrying the status code, so a caller can render 503 differently. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    // Findings and coverage are derived from a pinned analysis window, so the
    // response is stable until the next ingest. Caching it briefly keeps a
    // refresh from re-running the query without hiding a real change for long.
    next: { revalidate: 10 },
  });

  if (!response.ok) {
    // The backend reports *why* it is unhealthy in `detail`; surfacing that is
    // the difference between "something broke" and "the coverage manifest does
    // not declare proxy_zscaler".
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      // Non-JSON error body; the status line is all we have.
    }
    throw new ApiError(response.status, detail);
  }

  return (await response.json()) as T;
}

export function fetchHealth(): Promise<HealthResponse> {
  return get<HealthResponse>("/api/health");
}

export function fetchPersonas(): Promise<PersonaListResponse> {
  return get<PersonaListResponse>("/api/personas");
}
