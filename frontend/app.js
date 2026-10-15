let btn = document.querySelector(".gen_keys");
let resetBtn = document.querySelector(".reset");

document.addEventListener("DOMContentLoaded", () => {
  btn.addEventListener("click", async () => {
    let primeType = document.getElementById("prime_type").value;
    let bits = parseInt(document.getElementById("bits").value);
    let plainText = document.getElementById("plaintext").value;

    try {
      const response = await fetch(
        "/api/generate-and-analyze/",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            prime_type: primeType,
            bits: bits,
            test_message: plainText,
          }),
        }
      );

      const data = await response.json();

      //General result

      document.querySelector(".status_value").textContent = data.success;
      console.log(data.success);
      document.querySelector(".p_value").textContent = data.keys.primes.p;
      document.querySelector(".q_value").textContent = data.keys.primes.q;
      document.querySelector(".n_value").textContent = data.keys.public_key.n;
      document.querySelector(".phi_value").textContent =
        data.keys.metadata.bit_length;
      document.querySelector(".pub_value").textContent = data.keys.public_key.e;
      document.querySelector(".priv_value").textContent =
        data.keys.private_key.d;
      document.getElementById("output-message").innerText = data.analysis.encryption_test.ciphertext;

      let fact = data.analysis.strength_analysis.factorization_attempts;
      let facts = data.analysis.strength_analysis.time_estimates;

      //Trial division
      document.querySelector(".tmethod_value").textContent = fact[0].method;
      document.querySelector(".tsuccess_value").textContent = fact[0].success;
      document.querySelector(".tRuntime_value").textContent =
        fact[0].time_taken;
      document.querySelector(".tAttempts_value").textContent = fact[0].attempts;
      if (fact[0].success === true) {
        document.querySelector(".z").style.visibility = "hidden";
        document.querySelector(".result").style.height = "200px";
      } else {
        document.querySelector(".estsec_value").textContent =
          facts.trial_division.estimated_seconds;
        document.querySelector(".estyears_value").textContent =
          facts.trial_division.estimated_years;
        document.querySelector(".estops_value").textContent =
          facts.trial_division.estimated_operations;
      }

      //Pollard's Rho
      document.querySelector(".pmethod_value").textContent = fact[1].method;
      document.querySelector(".psuccess_value").textContent = fact[1].success;
      document.querySelector(".pRuntime_value").textContent =
        fact[1].time_taken;
      document.querySelector(".pAttempts_value").textContent = fact[1].attempts;

      if (fact[1].success === true) {
        document.querySelector(".p").style.visibility = "hidden";
        document.querySelector(".result").style.height = "200px";
      } else {
        document.querySelector(".estpsec_value").textContent =
          facts.pollard_rho.estimated_seconds;
        document.querySelector(".estpyears_value").textContent =
          facts.pollard_rho.estimated_years;
        document.querySelector(".estpops_value").textContent =
          facts.pollard_rho.estimated_operations;
      }

      //Fermat's method
      document.querySelector(".fmethod_value").textContent = fact[2].method;
      document.querySelector(".fsuccess_value").textContent = fact[2].success;
      document.querySelector(".fRuntime_value").textContent =
        fact[2].time_taken;
      document.querySelector(".fAttempts_value").textContent = fact[2].attempts;

      if (fact[2].success === true) {
        document.querySelector(".f").style.visibility = "hidden";
        document.querySelector(".result").style.height = "200px";
      } else {
        document.querySelector(".estfsec_value").textContent =
          facts.quadratic_sieve.estimated_seconds;
        document.querySelector(".estfyears_value").textContent =
          facts.quadratic_sieve.estimated_years;
        document.querySelector(".estfops_value").textContent =
          facts.quadratic_sieve.estimated_operations;
      }
    } catch (error) {
      document.querySelector(".status_value").textContent =
        "Error: " + error.message;
    }
  });
});

resetBtn.addEventListener("click", () => {
  document.getElementById("prime_type").value = "";
  document.getElementById("bits").value = "";
  document.getElementById("plaintext").value = "";
  document.querySelector(".status_value").textContent = "__";
  document.querySelector(".p_value").textContent = "__";
  document.querySelector(".q_value").textContent = "__";
  document.querySelector(".n_value").textContent = "__";
  document.querySelector(".phi_value").textContent = "__";
  document.querySelector(".tmethod_value").textContent = "__";
  document.querySelector(".tsuccess_value").textContent = "__";
  document.querySelector(".tRuntime_value").textContent = "__";
  document.querySelector(".tAttempts_value").textContent = "__";
  document.getElementById("output-message").innerText = "__";

  //Pollard's Rho
  document.querySelector(".pmethod_value").textContent = "__";
  document.querySelector(".psuccess_value").textContent = "__";
  document.querySelector(".pRuntime_value").textContent = "__";
  document.querySelector(".pAttempts_value").textContent = "__";

  //Fermat's method
  document.querySelector(".fmethod_value").textContent = "__";
  document.querySelector(".fsuccess_value").textContent = "__";
  document.querySelector(".fRuntime_value").textContent = "__";
  document.querySelector(".fAttempts_value").textContent = "__";
  document.querySelector(".estfsec_value").textContent = "__";
  document.querySelector(".estfyears_value").textContent = "__";
  document.querySelector(".estfops_value").textContent = "__";
  document.querySelector(".estpsec_value").textContent = "__";
  document.querySelector(".estpyears_value").textContent = "__";
  document.querySelector(".estpops_value").textContent = "__";
  document.querySelector(".estsec_value").textContent = "__";
  document.querySelector(".estyears_value").textContent = "__";
  document.querySelector(".estops_value").textContent = "__";

  document.querySelector(".pub_value").textContent = "__";
  document.querySelector(".priv_value").textContent = "__";
});
