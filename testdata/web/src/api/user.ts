import * as Sentry from "@sentry/react";
import axios from "axios";
import mixpanel from "mixpanel-browser";
import { maskEmail, logInfo } from "../lib/mask";

export interface User {
  id: string;
  email: string;
  phoneNumber?: string;
  nationalId: string;
}

export class UserService {
  constructor(private readonly baseUrl: string) {}

  async register(user: User, birthDate: string) {
    Sentry.setUser({ id: user.id, email: user.email });
    mixpanel.track("Signed Up", { phone: user.phoneNumber });
    localStorage.setItem("dob", birthDate);
    await axios.post("https://api.partner-crm.io/v1/leads", { nationalId: user.nationalId });
    console.log(`registered ${maskEmail(user.email)}`);
    logInfo("user registered", user.phoneNumber);
    return fetch(`${this.baseUrl}/users`, { method: "POST", body: JSON.stringify(user) });
  }
}

export const onLogin = ({ email }: { email: string }) => {
  window.localStorage.setItem("lastEmail", email);
};
