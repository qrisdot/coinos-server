import { bail, fail } from "$lib/utils";
import got from "got";
import config from "$config";
import { l, warn } from "$lib/logging";
import { SESClient } from "@aws-sdk/client-ses";
import { SendEmailCommand } from "@aws-sdk/client-ses";

// reCAPTCHA v3 never challenges: siteverify returns success:true for any
// well-formed token and reports how human the request looked in `score`.
// Checking `success` alone let a headless scanner submit freely.
const MIN_SCORE = 0.5;

const escapeHtml = (s: string) =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

// Strip CR/LF and other control characters from single-line header values.
const oneLine = (s: string) => s.replace(/[\x00-\x1f\x7f]+/g, " ").trim();

export default {
  async send({ body, headers }, res) {
    try {
      const { email, message, username, token: response } = body;
      if (typeof message !== "string" || !message.trim()) fail("Message required");
      if (typeof email !== "string" || !email.trim()) fail("Email required");
      if (username != null && typeof username !== "string") fail("Invalid username");
      if (typeof response !== "string" || !response) fail("failed captcha");

      const Charset = "UTF-8";

      const { recaptcha: secret } = config;
      const remoteip = headers?.["cf-connecting-ip"];
      const { success, score, action } = await got
        .post("https://www.google.com/recaptcha/api/siteverify", {
          form: { secret, response, ...(remoteip && { remoteip }) },
          timeout: { request: 6000 },
        })
        .json<any>();

      if (!success || action !== "submit" || !(score >= MIN_SCORE)) {
        warn("support request rejected", email, "score", score, "action", action);
        fail("failed captcha");
      }

      l("support request from", email, "score", score);
      const name = username ? oneLine(username).slice(0, 100) : "";
      const client = new SESClient({ region: "us-east-2" });
      await client.send(
        new SendEmailCommand({
          Destination: {
            CcAddresses: [],
            ToAddresses: [config.support],
          },
          Message: {
            Body: {
              Html: { Charset, Data: escapeHtml(message).replace(/\n/g, "<br>") },
              Text: { Charset, Data: message },
            },
            Subject: {
              Charset,
              Data: `Support Request${name ? ` From ${name}` : ""}`,
            },
          },
          ReplyToAddresses: [oneLine(email)],
          Source: config.support,
        }),
      );

      res.send({ ok: true });
    } catch (e) {
      bail(res, e.message);
    }
  },
};
