from transformers import AutoModelForCausalLM, AutoTokenizer

# Choose a model (GPT-J is a good balance for local use)
model_name = "EleutherAI/gpt-j-6B"  # Alternatively, use 'EleutherAI/gpt-neo-2.7B' for a smaller model

# Load the model and tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

def generate_text(prompt):
    inputs = tokenizer(prompt, return_tensors="pt")
    outputs = model.generate(**inputs, max_length=100)
    return tokenizer.decode(outputs[0], skip_special_tokens=True)

print(generate_text("Explain the basics of cybersecurity."))
