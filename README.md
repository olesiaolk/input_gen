# input_gen

`input_gen` is a small utility for generating adversarial and risk-oriented test inputs for LLM evaluations with `deepteam`.

The project reads enabled vulnerabilities from [`data/vulnerabilities.csv`](/Users/admin/PycharmProjects/input_gen/data/vulnerabilities.csv) and enabled transformation strategies from [`data/strategies.csv`](/Users/admin/PycharmProjects/input_gen/data/strategies.csv), generates base attack prompts, applies selected obfuscation or jailbreak-style strategies, and saves the final dataset to the [`output_data/`](/Users/admin/PycharmProjects/input_gen/output_data) directory as CSV.

It supports:

- built-in `deepteam` vulnerability types such as PII leakage, bias, toxicity, misinformation, and illegal activity
- configurable attack strategies including `Base64`, `ROT13`, `PromptInjection`, `Roleplay`, `GrayBox`, and optional legacy-compatible mappings
- custom vulnerabilities via [`my_plugins.py`](/Users/admin/PycharmProjects/input_gen/my_plugins.py)
- runtime configuration through `.env`
- retry handling for transient OpenAI API errors

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Create a `.env` file based on [` .env.example`](/Users/admin/PycharmProjects/input_gen/.env.example) and set the values you need:

```env
OPENAI_MODEL=gpt-4o-mini
MAX_GOLDENS=1
TARGET_PURPOSE=A helpful AI assistant
OPENAI_MAX_RETRIES=3
```

## Usage

Run the generator with the default CSV configuration:

```bash
python generate_attacks.py
```

Or pass files explicitly:

```bash
python generate_attacks.py \
  --vuln_file data/vulnerabilities.csv \
  --strat_file data/strategies.csv \
  --plugins my_plugins.py \
  --count 1
```

## Output

The script creates a timestamped CSV file in `output_data/` with the following columns:

- `risk_factor`
- `type`
- `strategy`
- `is_transformed`
- `generated_input`
- `error`

This makes the project useful for preparing red-team style prompts, regression test inputs, and safety evaluation datasets for conversational AI systems.
