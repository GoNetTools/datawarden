// Examples for the TypeScript web request sources (internal/rules/builtin/requests.yaml).
import express, { Request, Response } from "express";
import { NextRequest } from "next/server";

declare function Body(key?: string): ParameterDecorator;

const app = express();

app.post("/signup", (req, res) => {
  // ruleid: src.ts.express_request, log.ts.console
  console.log(req.body);
  // ok: src.ts.express_request
  console.log(req.query.page);
  res.sendStatus(204);
});

function logPage(body: any) {
  console.log(body.page);
}

app.post("/search", (req, res) => {
  // A helper reading one named field of the body: the name says what it is.
  // ok: src.ts.express_request
  logPage(req.body);
  res.end();
});

export function typedHandler(req: Request, res: Response) {
  // ruleid: src.ts.express_request, log.ts.console
  console.log("signup", JSON.stringify(req.body));
  res.end();
}

export async function koaHandler(ctx: any) {
  // ruleid: src.ts.express_request, log.ts.console
  console.log(ctx.request.body);
}

export async function POST(request: NextRequest) {
  // ruleid: src.ts.fetch_request
  const payload = await request.json();
  // ruleid: log.ts.console
  console.log(payload);
}

export class SignupController {
  // ruleid: src.ts.nest_body
  create(@Body() dto: any, @Body("plan") plan: string) {
    // ruleid: log.ts.console
    console.log(dto);
    // ok: src.ts.nest_body
    console.log(plan);
  }
}
