# ============================================================
# PyGuard-IDS-IPS — Makefile
# ============================================================

PYTHON   := python3
PIP      := pip
IFACE    ?= eth0
TARGET   ?= 127.0.0.1

.PHONY: help install run run-ids run-nodash test simulate clean flush

help:
	@echo ""
	@echo "  PyGuard-IDS-IPS — Kullanılabilir Komutlar"
	@echo "  =========================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

install: ## Bağımlılıkları yükle
	$(PIP) install -r requirements.txt

run: ## Tüm bileşenlerle başlat (sudo gerekli)
	sudo $(PYTHON) main.py -i $(IFACE)

run-ids: ## Sadece IDS modu (iptables bloklama kapalı)
	sudo $(PYTHON) main.py -i $(IFACE) --no-ips

run-nodash: ## Dashboard olmadan çalıştır
	sudo $(PYTHON) main.py -i $(IFACE) --no-dash

test: ## Birim testlerini çalıştır
	$(PYTHON) -m pytest tests/ -v --tb=short

simulate: ## Tüm saldırı simülasyonlarını çalıştır
	sudo $(PYTHON) simulator.py --attack all --target $(TARGET) --count 120

clean: ## Log dosyalarını temizle
	rm -f logs/alerts.json logs/stats.json logs/stats.json.tmp

flush: ## iptables PYGUARD_BLOCK zincirini temizle (sudo gerekli)
	sudo iptables -F PYGUARD_BLOCK 2>/dev/null || true
	sudo iptables -D INPUT -j PYGUARD_BLOCK 2>/dev/null || true
	sudo iptables -X PYGUARD_BLOCK 2>/dev/null || true
