import { D } from "./hash.js";

/** usage_ids.payload_hash = D("WEATHER-USAGE/1", {delta, subject, unit}) (§3.3). */
export function usagePayloadHash(subject: string, delta: string, unit: "usd_micro"): string {
  return D("WEATHER-USAGE/1", { delta, subject, unit });
}
