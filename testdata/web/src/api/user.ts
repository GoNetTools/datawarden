import * as Sentry from "@sentry/react";
import axios from "axios";
import mixpanel from "mixpanel-browser";
import { maskEmail, logInfo } from "../lib/mask";

export interface User {
  id: string;
  email: string;
  soDienThoai?: string;
  cccd: string;
}

export class UserService {
  constructor(private readonly baseUrl: string) {}

  async register(user: User, ngaySinh: string) {
    Sentry.setUser({ id: user.id, email: user.email });
    mixpanel.track("Signed Up", { sdt: user.soDienThoai });
    localStorage.setItem("dob", ngaySinh);
    await axios.post("https://api.partner-crm.io/v1/leads", { cccd: user.cccd });
    console.log(`registered ${maskEmail(user.email)}`);
    logInfo("user registered", user.soDienThoai);
    return fetch(`${this.baseUrl}/users`, { method: "POST", body: JSON.stringify(user) });
  }
}

export const onLogin = ({ email }: { email: string }) => {
  window.localStorage.setItem("lastEmail", email);
};
