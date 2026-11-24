/* ==========================================================================
   KM Campus - Master Client-Side Script
   ========================================================================== */

document.addEventListener("DOMContentLoaded", function () {
    
    // 1. Location Toggle Logic (Teghra Subdivision vs. Manual Entry)
    const subdivisionSelect = document.getElementById("subdivisionSelect");
    if (subdivisionSelect) {
        subdivisionSelect.addEventListener("change", toggleLocationFields);
        // Run once on load in case of browser autofill / back button state
        toggleLocationFields();
    }

    // 2. Client-Side File Size Validator (Prevents uploading oversized photos/docs)
    const uploadForm = document.getElementById("uploadForm") || document.querySelector("form[enctype='multipart/form-data']");
    if (uploadForm) {
        uploadForm.addEventListener("submit", function (e) {
            const photoInput = document.getElementById("photoInput");
            const frontInput = document.getElementById("frontInput");
            const backInput = document.getElementById("backInput");

            // Check Photo (Max 1MB)
            if (photoInput && photoInput.files[0]) {
                if (photoInput.files[0].size > 1 * 1024 * 1024) {
                    alert("⚠️ Profile photo size must be less than 1MB.");
                    e.preventDefault();
                    return;
                }
            }

            // Check Aadhaar Front/Back (Max 1.5MB each)
            if (frontInput && frontInput.files[0]) {
                if (frontInput.files[0].size > 1.5 * 1024 * 1024) {
                    alert("⚠️ Aadhaar Front scan size must be less than 1.5MB.");
                    e.preventDefault();
                    return;
                }
            }

            if (backInput && backInput.files[0]) {
                if (backInput.files[0].size > 1.5 * 1024 * 1024) {
                    alert("⚠️ Aadhaar Back scan size must be less than 1.5MB.");
                    e.preventDefault();
                    return;
                }
            }
        });
    }

    // 3. Extra Utility: Confirmation Prompts for Admin Actions (Delete/Reject)
    const deleteLinks = document.querySelectorAll(".btn-danger, a[href*='delete'], a[href*='reject']");
    deleteLinks.forEach(link => {
        link.addEventListener("click", function (e) {
            const confirmed = confirm("Are you sure you want to perform this action? This cannot be easily undone.");
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });

});

/**
 * Toggles visibility between Teghra predefined block fields and manual inputs
 */
function toggleLocationFields() {
    const subdivisionSelect = document.getElementById("subdivisionSelect");
    const teghraFields = document.getElementById("teghraFields");
    const manualFields = document.getElementById("manualFields");

    if (!subdivisionSelect || !teghraFields || !manualFields) return;

    const subVal = subdivisionSelect.value;

    if (subVal === "Teghra") {
        teghraFields.style.display = "block";
        manualFields.style.display = "none";
        
        // Make Teghra fields required / Manual fields optional
        setFieldsRequired(teghraFields, true);
        setFieldsRequired(manualFields, false);
    } else if (subVal === "Others") {
        teghraFields.style.display = "none";
        manualFields.style.display = "block";
        
        // Make Manual fields required / Teghra fields optional
        setFieldsRequired(teghraFields, false);
        setFieldsRequired(manualFields, true);
    } else {
        teghraFields.style.display = "none";
        manualFields.style.display = "none";
        setFieldsRequired(teghraFields, false);
        setFieldsRequired(manualFields, false);
    }
}

/**
 * Helper to dynamically toggle the 'required' attribute on container inputs
 */
function setFieldsRequired(container, isRequired) {
    const inputs = container.querySelectorAll("input, select");
    inputs.forEach(input => {
        // Skip readonly fields or hidden fields if any
        if (!input.readOnly) {
            input.required = isRequired;
        }
    });
}