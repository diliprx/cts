// 1. Hardcoded Secret (AWS Key pattern)
const AWS_ACCESS_KEY = "AKIAIMW667SS6377WJ5Q"; 

// 2. Dangerous eval() usage
function executeCode(userInput) {
    eval(userInput); // Critical vulnerability
}

// 3. XSS Vulnerability%
const params = new URLSearchParams(window.location.search);
const name = params.get("name");
document.getElementById("welcome").innerHTML = "Hello " + name; // Unsanitized input

// 4. Debugging leftover
console.log("Debug info: " + JSON.stringify(config));
debugger;
