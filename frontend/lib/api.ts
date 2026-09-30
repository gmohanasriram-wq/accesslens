/**
 * Typed client for the AccessLens backend.
 *
 * Server-side only. The base URL is read from `API_BASE_URL` without the
 * `NEXT_PUBLIC_` prefix, so it is never inlined into the client bundle and the
 * browser never talks to the backend directly. That is deliberate for Phase 1 —
 * the API is an internal service, and keeping it server-side means there is no
 * CORS surface and no backend address exposed to a reviewer's browser.
 */

import { cache } from "react";

import type {
  AnalysisResponse,
  FindingDossierResponse,
  HealthResponse,
  PersonaListResponse,
} from "@/types/api";

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

/*
 * Every fetcher below is wrapped in React's `cache`, which dedupes *within a
 * single render pass*. Two components on one page asking the same question --
 * the shell's provenance strip and the page body both want the persona list --
 * should cost one request, and the shell is rendered on every route, so this is
 * the common case rather than the exception. It is per-request, so it does not
 * interfere with the `revalidate` window above.
 */

export const fetchHealth = cache((): Promise<HealthResponse> => {
  return get<HealthResponse>("/api/health");
});

export const fetchPersonas = cache((): Promise<PersonaListResponse> => {
  return get<PersonaListResponse>("/api/personas");
});

export const fetchAnalysis = cache((): Promise<AnalysisResponse> => {
  return get<AnalysisResponse>("/api/analysis");
});

/**
 * One finding's full dossier.
 *
 * A 404 is not an error to render here -- it is the answer "there is no such
 * record", and the page turns it into `notFound()`. So the `ApiError` is left
 * for the caller to inspect rather than swallowed.
 */
export const fetchDossier = cache(
  (findingId: string): Promise<FindingDossierResponse> => {
    return get<FindingDossierResponse>(
      `/api/analysis/findings/${encodeURIComponent(findingId)}`,
    );
  },
);
