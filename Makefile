.PHONY: test
test: test-exe test-arc test-arc-exe test-so


.PHONY: test-exe
test-exe:
	@echo "============================================================="
	@echo "========== (Test 1) .o files --> .out executbale file"
	@echo "============================================================="
	@cd tests/bench1 && ./test1.sh
	@echo ""


.PHONY: test-arc
test-arc:
	@echo "============================================================="
	@echo "========== (Test 2) .o files --> .a archive file"
	@echo "============================================================="
	@cd tests/bench2 && ./test2.sh
	@echo ""


.PHONY: test-arc-exe
test-arc-exe:
	@echo "============================================================="
	@echo "========== (Test 3) .o and .a files --> .out executable file"
	@echo "============================================================="
	@cd tests/bench3 && ./test3.sh
	@echo ""


.PHONY: test-so
test-so:
	@echo "============================================================="
	@echo "========== (Test 4) .o files --> .so shared object file"
	@echo "============================================================="

	@echo ""

.PHONY: clean
clean:
	@echo "cleaned"

