// export type ApiResponse<T> = {
//   statusCode: number;
//   message: string;
//   data: T;
// };
export type ApiResponse<T = void> = ApiSuccess<T> | ApiFailure;

// Interfejs dla udanej odpowiedzi
export interface ApiSuccess<T> {
  statusCode: number;
  message: string;
  data: T;
}

// Interfejs dla nieudanej odpowiedzi
export interface ApiFailure {
  statusCode: number;
  message: string;
  error: string;
}
