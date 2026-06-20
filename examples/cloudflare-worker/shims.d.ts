declare module "*.wasm" {
  export function new_stream_context(token: string): any;
  export function execute_security_filter(ctx: any, secret: string, currentTime: number): void;
}