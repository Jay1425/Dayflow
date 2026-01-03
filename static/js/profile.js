// Profile page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    const tabButtons = document.querySelectorAll('[data-profile-tab]');
    const panels = document.querySelectorAll('[data-profile-panel]');
    
    function switchTab(tabName) {
        panels.forEach(panel => {
            if (panel.getAttribute('data-profile-panel') === tabName) {
                panel.classList.remove('hidden');
            } else {
                panel.classList.add('hidden');
            }
        });
        
        tabButtons.forEach(btn => {
            if (btn.getAttribute('data-profile-tab') === tabName) {
                btn.classList.add('bg-white/10', 'text-white');
            } else {
                btn.classList.remove('bg-white/10', 'text-white');
            }
        });
    }
    
    tabButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabName = this.getAttribute('data-profile-tab');
            switchTab(tabName);
        });
    });
    
    // Default to resume tab
    if (tabButtons.length > 0) {
        switchTab('resume');
    }
    
    // Edit profile functionality
    const btnEdit = document.getElementById('btn-edit-profile');
    const btnSave = document.getElementById('btn-save-profile');
    const btnCancel = document.getElementById('btn-cancel-edit');
    const editableFields = document.querySelectorAll('[data-editable="1"]');
    
    if (btnEdit) {
        btnEdit.addEventListener('click', function() {
            // Enable editable fields
            editableFields.forEach(field => {
                const canEdit = field.getAttribute('data-can-edit') === '1';
                const isHrOnly = field.getAttribute('data-hr-only') === '1';
                const viewerIsHr = field.getAttribute('data-viewer-hr') === '1';
                
                if (canEdit && (!isHrOnly || viewerIsHr)) {
                    field.disabled = false;
                }
            });
            
            // Show/hide buttons
            btnEdit.classList.add('hidden');
            btnSave.classList.remove('hidden');
            btnCancel.classList.remove('hidden');
            
            document.getElementById('edit-hint').textContent = 'Edit mode active. Save or cancel when done.';
        });
    }
    
    if (btnCancel) {
        btnCancel.addEventListener('click', function() {
            location.reload();
        });
    }
    
    // Profile photo upload with Cropper.js
    const photoInput = document.getElementById('profile-photo-input');
    const photoCropWrap = document.getElementById('photo-crop-wrap');
    const photoCropImage = document.getElementById('photo-crop-image');
    const btnUploadCropped = document.getElementById('btn-upload-cropped');
    let cropper = null;
    
    if (photoInput) {
        photoInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = function(event) {
                photoCropImage.src = event.target.result;
                photoCropWrap.classList.remove('hidden');
                
                if (cropper) {
                    cropper.destroy();
                }
                
                cropper = new Cropper(photoCropImage, {
                    aspectRatio: 1,
                    viewMode: 2,
                    autoCropArea: 0.8,
                    responsive: true,
                    background: false
                });
            };
            reader.readAsDataURL(file);
        });
    }
    
    if (btnUploadCropped) {
        btnUploadCropped.addEventListener('click', async function() {
            if (!cropper) return;
            
            const canvas = cropper.getCroppedCanvas({
                width: 400,
                height: 400
            });
            
            canvas.toBlob(async (blob) => {
                const formData = new FormData();
                formData.append('photo', blob, 'profile.png');
                
                const uploadUrl = this.getAttribute('data-upload-url');
                
                try {
                    const response = await fetch(uploadUrl, {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        alert('Profile photo updated successfully!');
                        location.reload();
                    } else {
                        alert('Error: ' + result.message);
                    }
                } catch (error) {
                    alert('Upload failed: ' + error.message);
                }
            });
        });
    }
    
    // Salary calculation (real-time)
    const monthlyWageInput = document.getElementById('salary-monthly-wage');
    const yearlyWageInput = document.getElementById('salary-yearly-wage');
    const employeePfInput = document.getElementById('employee-pf-percent');
    const employerPfInput = document.getElementById('employer-pf-percent');
    const professionalTaxInput = document.getElementById('professional-tax');
    
    function calculateSalary() {
        const monthlyWage = parseFloat(monthlyWageInput?.value || 0);
        const employeePfPercent = parseFloat(employeePfInput?.value || 12);
        const employerPfPercent = parseFloat(employerPfInput?.value || 12);
        const professionalTax = parseFloat(professionalTaxInput?.value || 200);
        
        // Calculate breakdown
        const yearlyWage = monthlyWage * 12;
        const basic = monthlyWage * 0.5;
        const hra = basic * 0.5;
        const standardAllowance = 1500;
        const performanceBonus = basic * 0.0833;
        const lta = basic * 0.08333;
        const totalComponents = basic + hra + standardAllowance + performanceBonus + lta;
        const fixedAllowance = Math.max(0, monthlyWage - totalComponents);
        const grossSalary = monthlyWage;
        
        // PF
        const employeePfAmount = basic * (employeePfPercent / 100);
        const employerPfAmount = basic * (employerPfPercent / 100);
        
        // Net salary
        const totalDeductions = employeePfAmount + professionalTax;
        const netSalary = grossSalary - totalDeductions;
        
        // Update displays
        const format = (num) => num.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        
        if (yearlyWageInput) yearlyWageInput.value = yearlyWage.toFixed(2);
        
        document.querySelector('[data-salary-out="basic"]').textContent = format(basic);
        document.querySelector('[data-salary-out="hra"]').textContent = format(hra);
        document.querySelector('[data-salary-out="standard_allowance"]').textContent = format(standardAllowance);
        document.querySelector('[data-salary-out="performance_bonus"]').textContent = format(performanceBonus);
        document.querySelector('[data-salary-out="lta"]').textContent = format(lta);
        document.querySelector('[data-salary-out="fixed_allowance"]').textContent = format(fixedAllowance);
        document.querySelector('[data-salary-out="gross_salary"]').textContent = format(grossSalary);
        document.querySelector('[data-salary-out="employee_pf_amount"]').textContent = format(employeePfAmount);
        document.querySelector('[data-salary-out="employer_pf_amount"]').textContent = format(employerPfAmount);
        document.querySelector('[data-salary-out="net_salary"]').textContent = format(netSalary);
    }
    
    // Attach listeners
    if (monthlyWageInput) {
        [monthlyWageInput, employeePfInput, employerPfInput, professionalTaxInput].forEach(input => {
            if (input) {
                input.addEventListener('input', calculateSalary);
            }
        });
        
        // Initial calculation
        calculateSalary();
    }
});
