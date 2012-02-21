RONN ?= ronn --organization="IITiS PAN Gliwice" --pipe

default: all
	-doxygen Doxyfile

all: \
	out/tracedump.1.man out/tracedump.1.html

index.txt: *.markdown
	./mkindex.sh

out/%.man : %.markdown index.txt
	mkdir -p out
	$(RONN) --roff $< > $@

out/%.html : %.markdown index.txt
	mkdir -p out
	$(RONN) --html --style=toc $< > $@

.PHONY: clean
clean:
	-rm -f out/*
