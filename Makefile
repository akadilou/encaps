BIN=./target/release/cryq8_cli

all: build
build:
	cargo build --release -p cryq8
	cargo build --release -p cryq8_cli
test:
	cargo test -p cryq8
encpwd:
	$(BIN) encpwd --password '$(P)' --inp $(IN) --out $(OUT) --mime $(MIME) --filename $(NAME)
decpwd:
	$(BIN) decpwd --password '$(P)' --inp $(IN) --out $(OUT)
enckp:
	$(BIN) enckp --sender-x25519-priv-b64 $(S_PRIV) --recipient-x25519-pub-b64 $(R_PUB) --inp $(IN) --out $(OUT) --mime $(MIME) --filename $(NAME) $(SIG)
deckp:
	$(BIN) deckp --recipient-x25519-priv-b64 $(R_PRIV) --inp $(IN) --out $(OUT) $(EXP)
keygen-x:
	$(BIN) keygen-x
keygen-ed:
	$(BIN) keygen-ed
keygen-x-json:
	$(BIN) keygen-x-json
keygen-ed-json:
	$(BIN) keygen-ed-json
spec:
	open SPEC_Encaps_v1.md
