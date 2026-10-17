export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly requestId: string,
  ) {
    super(`request failed (${status})${requestId ? `, request ID ${requestId}` : ""}`);
  }
}
