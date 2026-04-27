import { test, expect } from "@playwright/test";
import { installMockServices } from "./mock-services";

test("landing screen renders and Start is interactive", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await expect(page.getByTestId("start-button")).toBeVisible();
  await expect(page.getByTestId("start-button")).toBeEnabled();
});

test("Start → setup screen exposes the click-driven HiPKI flow", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await expect(page.getByTestId("setup-assets")).toBeVisible();
  await expect(page.getByTestId("setup-hipki")).toBeVisible();
  await expect(page.getByTestId("setup-pin")).toBeVisible();
  await expect(page.getByTestId("hipki-detect")).toBeVisible();

  await page.getByTestId("hipki-detect").click();
  // Mock HiPKI fixture has at least one card-bearing slot, so Read card unlocks.
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await expect(page.getByTestId("hipki-body")).toContainText(/Card/, {
    timeout: 10_000,
  });
});

// @real: needs real proving keys for load_pk + witness gen + prove. Mock-mode
// fixtures stop at warmup-asset-download; full-flow lives in prove-real.spec.ts.
test("@real full flow reaches result and holds proof on review gate", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();

  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await expect(page.getByTestId("hipki-body")).toContainText(/Card/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("123456");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/Locked/, {
    timeout: 10_000,
  });
  await expect(page.getByTestId("pin-lock-badge")).toBeVisible();

  // Continue enables once warmup finishes.
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 120_000,
  });
  await page.getByTestId("continue-button").click();

  // Ready gate — user must explicitly click Start proving.
  await expect(page.getByTestId("start-proving")).toBeVisible();
  await expect(page.getByTestId("ready-card")).toBeVisible();
  await page.getByTestId("start-proving").click();

  // Review gate — proofs are held in memory; user must explicitly Send.
  await expect(page.getByTestId("review-send")).toBeVisible({
    timeout: 10 * 60_000,
  });
  await expect(page.getByTestId("review-challenge")).toBeVisible();
  await expect(page.getByTestId("review-cert-size")).toContainText(/B/);

  await page.getByTestId("review-send").click();

  // Result — the mock verifier accepts when the body shape is well-formed.
  await expect(page.getByTestId("result-verified")).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.getByTestId("result-prove-again")).toBeVisible();

  // Clear cached assets returns the user to landing.
  await expect(page.getByTestId("result-clear-cache")).toBeVisible();
  await page.getByTestId("result-clear-cache").click();
  await expect(page.getByTestId("start-button")).toBeVisible({
    timeout: 30_000,
  });
});

test("@real retry from review routes through setup for PIN re-verify (no submit)", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await page.getByTestId("pin-input").fill("123456");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 120_000,
  });
  await page.getByTestId("continue-button").click();
  await page.getByTestId("start-proving").click();
  await expect(page.getByTestId("review-send")).toBeVisible({
    timeout: 10 * 60_000,
  });

  // Retry from review → back to setup with the PIN panel reset. Strict
  // single-use: session Pin was consumed during proving, user must
  // re-enter to run another proving attempt.
  await page.getByTestId("review-retry").click();
  await expect(page.getByTestId("setup-pin")).toBeVisible();
  await expect(page.getByTestId("pin-input")).toBeEnabled();
  await expect(page.getByTestId("pin-lock-badge")).toBeHidden();
});
