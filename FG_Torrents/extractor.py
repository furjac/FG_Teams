from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.action_chains import ActionChains
from time import sleep
from fake_useragent import UserAgent

def extract(url, proxy):
    options = webdriver.ChromeOptions()
    if proxy:
        pluginfile = "proxy_auth_plugin.zip"
        options.add_extension(pluginfile)
    ua = UserAgent()
    user_agent = ua.random
    options.add_argument("--headless=new")
    options.add_argument(f"user-agent={user_agent}")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-renderer-backgrounding")
    options.add_argument("--disable-background-timer-throttling")
    options.add_argument("--disable-backgrounding-occluded-windows")
    options.add_argument("--disable-client-side-phishing-detection")
    options.add_argument("--disable-crash-reporter")
    options.add_argument("--disable-oopr-debug-crash-dump")
    options.add_argument("--no-crash-upload")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-low-res-tiling")
    options.add_argument("--log-level=3")
    options.add_argument("--silent")
    options.add_extension("chrome.crx")
    options.add_experimental_option(
        "excludeSwitches", ["enable-logging"])
    options.add_argument("--log-level=3")

    driver = webdriver.Chrome(options=options)
    driver.set_script_timeout(30)
    driver.get(url)
    click = WebDriverWait(driver, 10).until(EC.element_to_be_clickable(
        (By.CSS_SELECTOR, '#embed-player > div.main-content > div.play-btn')))
    ActionChains(driver).move_to_element(click).click(click).perform()
    WebDriverWait(driver, 10).until(
        EC.frame_to_be_available_and_switch_to_it((By.ID, 've-iframe')))
    
    sleep(30)
    
    src = driver.execute_script("return document.documentElement.outerHTML;")

    with open('frames.html', 'w') as f:
        f.write(src)
        f.close()

    driver.quit()
    raise SystemExit
