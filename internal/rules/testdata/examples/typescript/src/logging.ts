// Examples for the TypeScript logging sinks (internal/rules/builtin/typescript.yaml).
import winston from "winston";

const logger = winston.createLogger({ level: "info" });

export function consoleLog(email: string, orderId: string) {
  // ruleid: log.ts.console
  console.log("signup", email);
  // ok: log.ts.console
  console.log("order", orderId);
}

export function appLogger(phoneNumber: string) {
  // ruleid: log.ts.logger
  logger.info(`otp sent to ${phoneNumber}`);
}
