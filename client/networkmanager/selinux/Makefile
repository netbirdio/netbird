MODULE := nm_netbird_local

.PHONY: install uninstall clean

$(MODULE).pp: $(MODULE).te
	checkmodule -M -m -o $(MODULE).mod $(MODULE).te
	semodule_package -o $(MODULE).pp -m $(MODULE).mod

install: $(MODULE).pp
	semodule -i $(MODULE).pp

uninstall:
	semodule -r $(MODULE)

clean:
	rm -f $(MODULE).mod $(MODULE).pp
