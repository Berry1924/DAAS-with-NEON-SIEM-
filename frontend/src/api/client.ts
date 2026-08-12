export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail || message;
  }
}

export async function request<T>(
  path: string,
  options: RequestInit = {},
  onUnauthorized?: () => void
): Promise<T> {
  try {
    const response = await fetch(path, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...options.headers,
      },
    });

    if (response.status === 401 && onUnauthorized) {
      onUnauthorized();
    }

    const rawBody = await response.text();
    let body: unknown = null;
    if (rawBody) {
      try {
        body = JSON.parse(rawBody);
      } catch {
        /* Raw response */
      }
    }

    if (!response.ok) {
      const detail =
        typeof body === 'object' && body && 'detail' in body
          ? String((body as { detail: unknown }).detail)
          : rawBody || `${response.status} ${response.statusText}`;

      throw new ApiError(response.status, `Request failed (${response.status}): ${detail}`, detail);
    }

    if (body === null) {
      throw new ApiError(response.status, 'Backend returned empty or non-JSON response.');
    }

    return body as T;
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(0, err instanceof Error ? err.message : 'Network error connecting to backend.');
  }
}
