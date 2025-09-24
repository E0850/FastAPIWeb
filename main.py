from fastapi import FastAPI
from fastapi.responses import RedirectResponse

# Load the existing main.py content
with open("main.py", "r") as f:
    lines = f.readlines()

# Check if root route already exists
root_route_exists = any("@app.get(\"/\")" in line for line in lines)

# If not, append the redirect route to /docs
if not root_route_exists:
    lines.append("\n")
    lines.append("@app.get(\"/\")\n")
    lines.append("def redirect_to_docs():\n")
    lines.append("    return RedirectResponse(url='/docs')\n")

# Save the modified file
with open("main.py", "w") as f:
    f.writelines(lines)

print("Root route added to redirect to /docs. You can now visit https://fastapiweb-1.onrender.com/ and it will redirect to the Swagger UI.")

@app.get("/")
def redirect_to_docs():
    return RedirectResponse(url='/docs')
