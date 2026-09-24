export function maskEmail(email: string): string {
  const [user, domain] = email.split("@");
  return user.slice(0, 1) + "***@" + domain;
}

export function logInfo(message: string, data?: unknown) {
  console.info(message, data);
}
