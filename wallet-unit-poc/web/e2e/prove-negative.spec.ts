// Negative-path coverage: each test installs a mock shape that breaks one
// stage and asserts the UI surfaces the failure cleanly (no infinite
// spinner, no swallowed error, a way back).

import { test, expect } from "@playwright/test";
import { installMockServices } from "./mock-services";

test("wrong PIN decrements the attempt counter and locks at zero", async ({
  page,
}) => {
  await installMockServices(page, { signRejectsPin: true });
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await expect(page.getByTestId("hipki-body")).toContainText(/Card/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("000000");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/2 attempts left/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("000001");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/1 attempts left/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("000002");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/Card is locked/, {
    timeout: 10_000,
  });
  await expect(page.getByTestId("pin-input")).toBeDisabled();
  await expect(page.getByTestId("pin-verify")).toBeDisabled();
});

test("@real verifier 500 surfaces on submit and leaves Prove-again reachable", async ({
  page,
}) => {
  await installMockServices(page, { linkVerifyStatus: 500 });
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();

  await page.getByTestId("pin-input").fill("123456");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/Locked/, {
    timeout: 10_000,
  });
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 120_000,
  });
  await page.getByTestId("continue-button").click();
  await page.getByTestId("start-proving").click();

  // Proofs generate fine; the 500 hits when the user clicks Send.
  await expect(page.getByTestId("review-send")).toBeVisible({
    timeout: 10 * 60_000,
  });
  await page.getByTestId("review-send").click();

  // Submit failure routes to the error screen; Prove again / Home
  // buttons are visible so the user is never stuck.
  await expect(page.getByTestId("result-error")).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.getByTestId("result-prove-again")).toBeVisible();
});
