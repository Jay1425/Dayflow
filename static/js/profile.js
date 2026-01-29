// Profile page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    const tabButtons = document.querySelectorAll('.profile-tab');
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
            if (btn.getAttribute('data-tab') === tabName) {
                btn.classList.add('bg-primary-500/30', 'text-white');
                btn.classList.remove('text-gray-300', 'hover:text-white', 'hover:bg-white/10');
            } else {
                btn.classList.remove('bg-primary-500/30', 'text-white');
                btn.classList.add('text-gray-300', 'hover:text-white', 'hover:bg-white/10');
            }
        });
    }
    
    tabButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
    
    // Default to personal tab
    if (tabButtons.length > 0) {
        switchTab('personal');
    }
    
    // Profile photo upload with Cropper.js
    const photoInput = document.getElementById('profile-photo-input');
    const photoCropWrap = document.getElementById('photo-crop-wrap');
    const photoCropPreview = document.getElementById('photo-crop-preview');
    const btnUploadPhoto = document.getElementById('btn-upload-photo');
    const btnCancelPhoto = document.getElementById('btn-cancel-photo');
    const photoMessage = document.getElementById('photo-message');
    let cropper = null;
    
    if (photoInput) {
        photoInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = function(event) {
                photoCropPreview.src = event.target.result;
                photoCropWrap.classList.remove('hidden');
                
                if (cropper) {
                    cropper.destroy();
                }
                
                cropper = new Cropper(photoCropPreview, {
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
    
    if (btnCancelPhoto) {
        btnCancelPhoto.addEventListener('click', function() {
            if (cropper) {
                cropper.destroy();
                cropper = null;
            }
            photoCropWrap.classList.add('hidden');
            photoInput.value = '';
        });
    }
    
    if (btnUploadPhoto) {
        btnUploadPhoto.addEventListener('click', async function() {
            if (!cropper) return;
            
            btnUploadPhoto.disabled = true;
            btnUploadPhoto.disabled = true;
            btnUploadPhoto.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Uploading...';
            
            try {
                const canvas = cropper.getCroppedCanvas({
                    width: 400,
                    height: 400
                });
                
                canvas.toBlob(async (blob) => {
                    const formData = new FormData();
                    formData.append('photo', blob, 'profile.png');
                    
                    const uploadUrl = btnUploadPhoto.getAttribute('data-upload-url') || window.location.pathname + '/photo';
                    
                    try {
                        const response = await fetch(uploadUrl, {
                            method: 'POST',
                            body: formData
                        });
                        
                        if (response.ok) {
                            photoMessage.textContent = 'Profile photo updated successfully!';
                            photoMessage.className = 'text-sm text-green-400 mb-3';
                            setTimeout(() => location.reload(), 1500);
                        } else {
                            throw new Error('Upload failed');
                        }
                    } catch (error) {
                        photoMessage.textContent = 'Upload failed: ' + error.message;
                        photoMessage.className = 'text-sm text-red-400 mb-3';
                        btnUploadPhoto.disabled = false;
                        btnUploadPhoto.innerHTML = '<i class="fas fa-check mr-2"></i>Upload';
                    }
                });
            } catch (error) {
                photoMessage.textContent = 'Error processing image: ' + error.message;
                photoMessage.className = 'text-sm text-red-400 mb-3';
                btnUploadPhoto.disabled = false;
                btnUploadPhoto.innerHTML = '<i class="fas fa-check mr-2"></i>Upload';
            }
        });
    }
    
    // Salary calculation (real-time) - only if salary inputs exist
    const monthlyWageInput = document.querySelector('input[name="monthly_wage"]');
    const employeePfInput = document.querySelector('input[name="employee_pf_percent"]');
    const employerPfInput = document.querySelector('input[name="employer_pf_percent"]');
    const professionalTaxInput = document.querySelector('input[name="professional_tax"]');
    
    if (monthlyWageInput) {
        function calculateSalary() {
            const monthlyWage = parseFloat(monthlyWageInput.value || 0);
            const employeePfPercent = parseFloat(employeePfInput?.value || 12);
            const employerPfPercent = parseFloat(employerPfInput?.value || 12);
            const professionalTax = parseFloat(professionalTaxInput?.value || 200);
            
            // Calculate breakdown
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
            
            // Update displays if they exist
            const format = (num) => '₹' + num.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            
            // Log calculated values for debugging
            console.log('Calculated Gross:', grossSalary, 'Net:', netSalary);
        }
        
        // Attach listeners
        [monthlyWageInput, employeePfInput, employerPfInput, professionalTaxInput].forEach(input => {
            if (input) {
                input.addEventListener('input', calculateSalary);
            }
        });
    }
});
