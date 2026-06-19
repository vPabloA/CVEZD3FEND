from __future__ import annotations

import time
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

OUT = Path("web/docs/screenshots")
OUT.mkdir(parents=True, exist_ok=True)

options = webdriver.ChromeOptions()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--window-size=1600,1100")
options.add_argument("--force-device-scale-factor=1")

driver = webdriver.Chrome(options=options)
wait = WebDriverWait(driver, 60)


def snap(selector: str, name: str) -> None:
    element = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, selector)))
    driver.execute_script("arguments[0].scrollIntoView({block: 'start'});", element)
    time.sleep(0.8)
    element.screenshot(str(OUT / name))


try:
    driver.get("http://127.0.0.1:5173/#/analyze")
    wait.until(EC.visibility_of_element_located((By.ID, "multi-cve-analysis-form")))
    textarea = driver.find_element(By.ID, "batch-cves")
    textarea.send_keys("CVE-2025-0168\nCVE-2026-0544\nCVE-2025-99999999, invalid")
    driver.find_element(By.ID, "technologies").send_keys("Windows, Active Directory")
    for name, value in [
        ("exposure", "internet-facing"),
        ("exposure", "production"),
        ("priorities", "initial access"),
        ("priorities", "credential theft"),
    ]:
        checkbox = driver.find_element(By.CSS_SELECTOR, f'input[name="{name}"][value="{value}"]')
        driver.execute_script("arguments[0].click();", checkbox)
    Select(driver.find_element(By.ID, "audience")).select_by_visible_text("SOC")
    Select(driver.find_element(By.ID, "top-k")).select_by_visible_text("5")
    snap("#multi-cve-analysis-form", "multi-cve-01-input-context.png")

    analyze = next(button for button in driver.find_elements(By.TAG_NAME, "button") if "Analyze CVEs" in button.text)
    analyze.click()
    wait.until(EC.visibility_of_element_located((By.ID, "decision-summary")))
    wait.until(lambda d: "202" in d.find_element(By.ID, "decision-summary").text)
    snap("#decision-summary", "multi-cve-04-partial-success.png")
    snap("#analysis-workbench", "multi-cve-02-selected-graph-ranking.png")

    trace_step = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, '#threat-defense-graph button[aria-label^="Trace step 1"]')))
    trace_step.click()
    snap("#batch-evidence", "multi-cve-05-route-evidence.png")
    snap("#batch-narrative", "multi-cve-06-narrative.png")

    all_button = next(button for button in driver.find_elements(By.CSS_SELECTOR, '[role="tab"]') if "all" in button.text.lower())
    all_button.click()
    wait.until(EC.visibility_of_element_located((By.ID, "candidate-route-universe")))
    wait.until(lambda d: "Complete universe" in d.find_element(By.ID, "threat-defense-graph").text)
    snap("#analysis-workbench", "multi-cve-03-all-candidates.png")
finally:
    driver.quit()

expected = {
    "multi-cve-01-input-context.png",
    "multi-cve-02-selected-graph-ranking.png",
    "multi-cve-03-all-candidates.png",
    "multi-cve-04-partial-success.png",
    "multi-cve-05-route-evidence.png",
    "multi-cve-06-narrative.png",
}
actual = {path.name for path in OUT.glob("multi-cve-*.png")}
assert expected <= actual, (expected, actual)
for path in OUT.glob("multi-cve-*.png"):
    assert path.stat().st_size > 5_000, path
