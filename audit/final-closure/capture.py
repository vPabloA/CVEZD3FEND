from pathlib import Path
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

out = Path("web/docs/screenshots")
out.mkdir(parents=True, exist_ok=True)
options = webdriver.ChromeOptions()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--window-size=1600,1200")
driver = webdriver.Chrome(options=options)
wait = WebDriverWait(driver, 90)


def shot(selector: str, name: str) -> None:
    element = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, selector)))
    driver.execute_script("arguments[0].scrollIntoView({block: 'start'});", element)
    time.sleep(1)
    element.screenshot(str(out / name))


try:
    driver.get("http://127.0.0.1:5173/#/analyze")
    wait.until(EC.visibility_of_element_located((By.ID, "multi-cve-analysis-form")))
    driver.find_element(By.ID, "batch-cves").send_keys("CVE-2025-0168\nCVE-2026-0544\nCVE-2025-99999999, invalid")
    driver.find_element(By.ID, "technologies").send_keys("Windows, Active Directory")
    for group, value in [("exposure", "internet-facing"), ("exposure", "production"), ("priorities", "initial access"), ("priorities", "credential theft")]:
        checkbox = driver.find_element(By.CSS_SELECTOR, f'input[name="{group}"][value="{value}"]')
        driver.execute_script("arguments[0].click();", checkbox)
    Select(driver.find_element(By.ID, "audience")).select_by_visible_text("SOC")
    Select(driver.find_element(By.ID, "top-k")).select_by_visible_text("5")
    ai = driver.find_element(By.XPATH, "//span[normalize-space()='AI-assisted reranking']/ancestor::label//input")
    driver.execute_script("arguments[0].click();", ai)
    next(button for button in driver.find_elements(By.TAG_NAME, "button") if "Analyze CVEs" in button.text).click()

    wait.until(EC.visibility_of_element_located((By.ID, "decision-summary")))
    wait.until(lambda d: "202" in d.find_element(By.ID, "decision-summary").text)
    shot("#decision-summary", "multi-cve-04-partial-success.png")
    wait.until(EC.visibility_of_element_located((By.XPATH, "//*[normalize-space()='Deterministic fallback']")))
    assert "Human review required" not in driver.page_source

    all_button = next(button for button in driver.find_elements(By.CSS_SELECTOR, '[role="tab"]') if "all" in button.text.lower())
    all_button.click()
    wait.until(EC.visibility_of_element_located((By.ID, "candidate-route-universe")))
    wait.until(lambda d: "Complete universe" in d.find_element(By.ID, "threat-defense-graph").text)
    graph_text = driver.find_element(By.ID, "threat-defense-graph").text
    assert "This route is partial" not in graph_text
    for expected in ["CVE-2025-0168", "CWE-74", "CAPEC-13", "T1574.007", "D3-LFP", "Deterministic fallback", "Catalog-backed"]:
        assert expected in graph_text, expected
    shot("#analysis-workbench", "multi-cve-03-all-candidates.png")
    shot("#threat-defense-graph", "multi-cve-07-focused-route-truth.png")
finally:
    driver.quit()

for name in ["multi-cve-03-all-candidates.png", "multi-cve-04-partial-success.png", "multi-cve-07-focused-route-truth.png"]:
    path = out / name
    assert path.exists() and path.stat().st_size > 5000, path
