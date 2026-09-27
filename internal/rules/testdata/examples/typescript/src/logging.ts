// Examples for the TypeScript logging sinks (internal/rules/builtin/typescript.yaml).
import winston from "winston";
import pino from "pino";
import bunyan from "bunyan";

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

const log = pino();
const auditLogger = bunyan.createLogger({ name: "audit" });

export function pinoLogger(email: string, orderId: string) {
  // ruleid: log.ts.logger
  log.info({ email }, "signup");
  // ok: log.ts.logger
  log.info({ orderId }, "order placed");
}

export function bunyanLogger(nationalId: string) {
  // ruleid: log.ts.logger
  auditLogger.warn("id check failed for %s", nationalId);
}

export function fastifyRequestLogger(req: any, phoneNumber: string) {
  // ruleid: log.ts.logger
  req.log.info(`verifying ${phoneNumber}`);
}
