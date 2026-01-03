// ========================================
// Main JavaScript for HackathonApp (Tailwind Version)
// ========================================

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initLoader();
    initNavigation();
    initScrollAnimations();
    initBackToTop();
    initCounters();
    initFlashMessages();
    initAttendance();
    
    console.log('🚀 HackathonApp (Tailwind) initialized successfully!');
});

// ========================================
// Loading Spinner
// ========================================
function initLoader() {
    const loader = document.getElementById('loading-spinner');
    
    // Hide loader after page load
    window.addEventListener('load', function() {
        setTimeout(() => {
            if (loader) {
                loader.style.opacity = '0';
                loader.style.visibility = 'hidden';
            }
        }, 500);
    });
    
    // Hide loader after 3 seconds as fallback
    setTimeout(() => {
        if (loader) {
            loader.style.opacity = '0';
            loader.style.visibility = 'hidden';
        }
    }, 3000);
}

// ========================================
// Navigation
// ========================================
function initNavigation() {
    const mobileMenuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    const navbar = document.querySelector('nav');
    
    // Mobile menu toggle
    if (mobileMenuButton && mobileMenu) {
        mobileMenuButton.addEventListener('click', function() {
            const isHidden = mobileMenu.classList.contains('hidden');
            
            if (isHidden) {
                mobileMenu.classList.remove('hidden');
                mobileMenuButton.innerHTML = '<i class="fas fa-times text-xl"></i>';
            } else {
                mobileMenu.classList.add('hidden');
                mobileMenuButton.innerHTML = '<i class="fas fa-bars text-xl"></i>';
            }
        });
        
        // Close mobile menu when clicking on a link
        const mobileNavLinks = mobileMenu.querySelectorAll('a');
        mobileNavLinks.forEach(link => {
            link.addEventListener('click', () => {
                mobileMenu.classList.add('hidden');
                mobileMenuButton.innerHTML = '<i class="fas fa-bars text-xl"></i>';
            });
        });
        
        // Close mobile menu when clicking outside
        document.addEventListener('click', function(e) {
            if (!mobileMenuButton.contains(e.target) && !mobileMenu.contains(e.target)) {
                mobileMenu.classList.add('hidden');
                mobileMenuButton.innerHTML = '<i class="fas fa-bars text-xl"></i>';
            }
        });
    }
    
    // Navbar scroll effect
    if (navbar) {
        window.addEventListener('scroll', function() {
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            
            if (scrollTop > 100) {
                navbar.style.backgroundColor = 'rgba(2, 6, 23, 0.98)';
                navbar.style.backdropFilter = 'blur(12px)';
            } else {
                navbar.style.backgroundColor = 'rgba(2, 6, 23, 0.95)';
                navbar.style.backdropFilter = 'blur(8px)';
            }
        });
    }
}

// ========================================
// Scroll Animations
// ========================================
function initScrollAnimations() {
    // Intersection Observer for scroll animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Add animate classes based on element classes
                if (entry.target.classList.contains('scroll-animate')) {
                    entry.target.classList.add('animate-fade-in');
                }
                
                // Special handling for stats counters
                if (entry.target.classList.contains('stats-item') || 
                    entry.target.querySelector('[data-target]')) {
                    animateCounters();
                }
                
                // Unobserve after animation
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    // Observe all elements with scroll-animate class
    const animatedElements = document.querySelectorAll('.scroll-animate, .stats-item');
    animatedElements.forEach(el => {
        observer.observe(el);
    });
}

// ========================================
// Counter Animation
// ========================================
function initCounters() {
    // Will be triggered by scroll observer
    // No immediate initialization needed
}

function animateCounters() {
    const counters = document.querySelectorAll('[data-target]');
    
    counters.forEach(counter => {
        const target = parseInt(counter.getAttribute('data-target'));
        const duration = 2000; // 2 seconds
        const step = target / (duration / 16); // 60fps
        let current = 0;
        
        const updateCounter = () => {
            if (current < target) {
                current += step;
                counter.textContent = Math.floor(current);
                requestAnimationFrame(updateCounter);
            } else {
                counter.textContent = target;
            }
        };
        
        updateCounter();
    });
}

// ========================================
// Back to Top Button
// ========================================
function initBackToTop() {
    const backToTopBtn = document.getElementById('back-to-top');
    
    if (backToTopBtn) {
        // Show/hide button based on scroll position
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                backToTopBtn.classList.remove('opacity-0', 'invisible');
                backToTopBtn.classList.add('opacity-100', 'visible');
            } else {
                backToTopBtn.classList.add('opacity-0', 'invisible');
                backToTopBtn.classList.remove('opacity-100', 'visible');
            }
        });
        
        // Smooth scroll to top
        backToTopBtn.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
}

// ========================================
// Flash Messages
// ========================================
function initFlashMessages() {
    const flashMessages = document.querySelectorAll('.flash-message');
    
    // Auto-dismiss flash messages after 5 seconds
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.style.transform = 'translateX(100%)';
            message.style.opacity = '0';
            setTimeout(() => {
                message.remove();
            }, 300);
        }, 5000);
    });
}

// ========================================
// Attendance Module
// ========================================
function initAttendance() {
    const checkInBtn = document.getElementById('btn-checkin');
    const checkOutBtn = document.getElementById('btn-checkout');
    const messageEl = document.getElementById('attendance-message');
    const statusBadge = document.getElementById('attendance-status-badge');
    const statusText = document.getElementById('attendance-status');
    const checkInText = document.getElementById('attendance-checkin-time');
    const checkOutText = document.getElementById('attendance-checkout-time');
    const durationText = document.getElementById('attendance-duration');
    const dateLabel = document.getElementById('attendance-date');
    const weekGrid = document.getElementById('attendance-week');

    if (!checkInBtn || !checkOutBtn || !weekGrid) {
        console.log('Attendance module: Not on attendance page, skipping initialization');
        return; // Not on attendance page
    }
    
    console.log('Attendance module: Initializing...');
    console.log('Check-in button:', checkInBtn);
    console.log('Check-out button:', checkOutBtn);

    const statusClassMap = {
        'Present': 'bg-green-500/20 border-green-400 text-green-200',
        'Half Day': 'bg-yellow-500/20 border-yellow-400 text-yellow-100',
        'Short Shift': 'bg-orange-500/20 border-orange-400 text-orange-100',
        'In Progress': 'bg-blue-500/20 border-blue-400 text-blue-100',
        'Not Started': 'bg-blue-500/20 border-blue-400 text-blue-100',
        'Absent': 'bg-red-500/20 border-red-400 text-red-100'
    };

    let timerInterval = null;

    function parseTime(timeStr) {
        // Parse "HH:MM AM/PM" format
        if (!timeStr || timeStr === '—') return null;
        const [time, period] = timeStr.split(' ');
        const [hours, minutes] = time.split(':').map(Number);
        let hour24 = hours;
        if (period === 'PM' && hours !== 12) hour24 += 12;
        if (period === 'AM' && hours === 12) hour24 = 0;
        
        const now = new Date();
        return new Date(now.getFullYear(), now.getMonth(), now.getDate(), hour24, minutes);
    }

    function formatDuration(totalSeconds) {
        const hrs = Math.floor(totalSeconds / 3600);
        const mins = Math.floor((totalSeconds % 3600) / 60);
        const secs = totalSeconds % 60;
        return `${hrs}h ${mins}m ${secs}s`;
    }

    function startTimer(checkInTime) {
        stopTimer(); // Clear any existing timer
        
        const checkInDate = parseTime(checkInTime);
        if (!checkInDate) return;

        function updateTimer() {
            const now = new Date();
            const elapsed = Math.floor((now - checkInDate) / 1000); // seconds
            durationText.textContent = formatDuration(elapsed);
            statusText.textContent = 'Working...';
        }

        updateTimer(); // Update immediately
        timerInterval = setInterval(updateTimer, 1000); // Update every second
    }

    function stopTimer() {
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    }

    function setActions(actions) {
        checkInBtn.disabled = !actions.can_check_in;
        checkOutBtn.disabled = !actions.can_check_out;
    }

    function setStatusBadge(status) {
        if (!statusBadge) return;
        statusBadge.className = 'px-4 py-2 rounded-full border text-sm font-semibold ' + (statusClassMap[status] || 'bg-blue-500/20 border-blue-400 text-blue-100');
        statusBadge.textContent = status;
    }

    function updateToday(today) {
        dateLabel.textContent = today.date_label;
        statusText.textContent = today.status;
        checkInText.textContent = today.check_in;
        checkOutText.textContent = today.check_out;
        durationText.textContent = today.duration;
        setStatusBadge(today.status);
        
        // Start timer if checked in but not checked out
        if (today.check_in !== '—' && today.check_out === '—') {
            startTimer(today.check_in);
        } else {
            stopTimer();
        }
    }

    function updateWeekly(week) {
        if (!week || !Array.isArray(week)) return;
        weekGrid.innerHTML = week.map(item => `
            <div class="p-4 rounded-xl bg-white/5 border border-white/10">
                <p class="text-gray-400 text-sm mb-1">${item.date}</p>
                <p class="text-white font-semibold">${item.status}</p>
                <div class="text-xs text-gray-300 mt-2 space-y-1">
                    <p>In: ${item.check_in}</p>
                    <p>Out: ${item.check_out}</p>
                    <p>Duration: ${item.duration}</p>
                </div>
            </div>
        `).join('');
    }

    function showMessage(text, success = true) {
        if (!messageEl) return;
        messageEl.textContent = text;
        messageEl.className = success ? 'text-sm text-green-300' : 'text-sm text-red-300';
        if (text) {
            setTimeout(() => messageEl.textContent = '', 4000);
        }
    }

    async function callAction(url) {
        try {
            showMessage('Processing...', true);
            
            // Disable both buttons during request
            checkInBtn.disabled = true;
            checkOutBtn.disabled = true;
            
            const res = await fetch(url, { 
                method: 'POST', 
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest' 
                },
                credentials: 'same-origin'
            });
            
            if (!res.ok) {
                const errorData = await res.json().catch(() => ({}));
                showMessage(errorData.message || `Error: ${res.status}`, false);
                // Re-enable buttons based on previous state
                setTimeout(() => {
                    checkInBtn.disabled = false;
                    checkOutBtn.disabled = false;
                }, 1000);
                return;
            }
            
            const data = await res.json();
            if (!data.success) {
                showMessage(data.message || 'Unable to update attendance.', false);
                // Re-enable buttons based on previous state
                setTimeout(() => {
                    checkInBtn.disabled = false;
                    checkOutBtn.disabled = false;
                }, 1000);
                return;
            }
            updateToday(data.today);
            updateWeekly(data.weekly);
            setActions(data.actions);
            showMessage(data.message || 'Updated.');
        } catch (err) {
            console.error('Attendance error:', err);
            showMessage('Network error. Please try again.', false);
            // Re-enable buttons on error
            setTimeout(() => {
                checkInBtn.disabled = false;
                checkOutBtn.disabled = false;
            }, 1000);
        }
    }

    checkInBtn.addEventListener('click', (e) => {
        e.preventDefault();
        console.log('Check-in button clicked');
        callAction('/attendance/check-in');
    });
    
    checkOutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        console.log('Check-out button clicked');
        callAction('/attendance/check-out');
    });

    // Initialize timer if already checked in
    const initialCheckIn = checkInText.textContent;
    const initialCheckOut = checkOutText.textContent;
    if (initialCheckIn !== '—' && initialCheckOut === '—') {
        startTimer(initialCheckIn);
    }
}

// ========================================
// Smooth Scroll for Anchor Links
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    
    anchorLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = this.getAttribute('href');
            
            if (target && target !== '#') {
                const element = document.querySelector(target);
                if (element) {
                    const offsetTop = element.getBoundingClientRect().top + window.pageYOffset - 80;
                    
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            }
        });
    });
});

// ========================================
// Enhanced Button Interactions
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    // Add ripple effect to buttons
    const buttons = document.querySelectorAll('[data-ripple]');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('div');
            ripple.classList.add('ripple-effect');
            
            const rect = button.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.cssText = `
                position: absolute;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.3);
                transform: scale(0);
                animation: ripple 0.6s linear;
                left: ${x}px;
                top: ${y}px;
                width: ${size}px;
                height: ${size}px;
                pointer-events: none;
            `;
            
            button.style.position = 'relative';
            button.style.overflow = 'hidden';
            button.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
});

// ========================================
// Card Hover Effects
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    const cards = document.querySelectorAll('[data-hover-lift]');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-8px) scale(1.02)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
    });
});

// ========================================
// Form Enhancements
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    const formInputs = document.querySelectorAll('[data-form-input]');
    
    formInputs.forEach(input => {
        // Add focus/blur effects
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('focused');
        });
        
        // Add validation feedback
        input.addEventListener('input', function() {
            if (this.checkValidity()) {
                this.classList.remove('border-red-500');
                this.classList.add('border-green-500');
            } else {
                this.classList.remove('border-green-500');
                this.classList.add('border-red-500');
            }
        });
    });
});

// ========================================
// Parallax Effects
// ========================================
function initParallax() {
    const parallaxElements = document.querySelectorAll('.animate-float');
    
    window.addEventListener('scroll', function() {
        const scrolled = window.pageYOffset;
        
        parallaxElements.forEach((element, index) => {
            const speed = (index + 1) * 0.05;
            const yPos = -(scrolled * speed);
            element.style.transform = `translateY(${yPos}px)`;
        });
    });
}

// Initialize parallax after DOM load
document.addEventListener('DOMContentLoaded', initParallax);

// ========================================
// Utility Functions
// ========================================

// Debounce function for scroll events
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Throttle function for scroll events  
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ========================================
// Performance Optimizations
// ========================================
const throttledScrollHandler = throttle(function() {
    // Add any scroll-heavy operations here if needed
}, 16); // ~60fps

window.addEventListener('scroll', throttledScrollHandler);

// ========================================
// Error Handling
// ========================================
window.addEventListener('error', function(e) {
    console.error('JavaScript error:', e.error);
});

// ========================================
// Accessibility Improvements
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    // Keyboard navigation support
    document.addEventListener('keydown', function(e) {
        // Close mobile menu with Escape key
        if (e.key === 'Escape') {
            const mobileMenu = document.getElementById('mobile-menu');
            const mobileMenuButton = document.getElementById('mobile-menu-button');
            
            if (mobileMenu && !mobileMenu.classList.contains('hidden')) {
                mobileMenu.classList.add('hidden');
                if (mobileMenuButton) {
                    mobileMenuButton.innerHTML = '<i class="fas fa-bars text-xl"></i>';
                }
            }
        }
    });
    
    // Improve focus visibility
    const focusableElements = document.querySelectorAll('a, button, input, textarea, select');
    
    focusableElements.forEach(element => {
        element.addEventListener('focus', function() {
            this.style.outline = '2px solid #38BDF8';
            this.style.outlineOffset = '2px';
        });
        
        element.addEventListener('blur', function() {
            this.style.outline = 'none';
        });
    });
});

// ========================================
// CSS Keyframes for Ripple Effect
// ========================================
const rippleStyles = `
    @keyframes ripple {
        to {
            transform: scale(2);
            opacity: 0;
        }
    }
`;

// Add ripple styles to the document
if (!document.getElementById('ripple-styles')) {
    const styleSheet = document.createElement('style');
    styleSheet.id = 'ripple-styles';
    styleSheet.textContent = rippleStyles;
    document.head.appendChild(styleSheet);
}

// ========================================
// Development Mode Features
// ========================================
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    console.log('🎯 HackathonApp Development Mode');
    console.log('📱 Viewport:', window.innerWidth + 'x' + window.innerHeight);
    console.log('🎨 Tailwind CSS loaded');
    
    // Add grid overlay toggle (Ctrl+G)
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'g') {
            e.preventDefault();
            toggleDebugGrid();
        }
    });
    
    function toggleDebugGrid() {
        let grid = document.getElementById('debug-grid');
        if (!grid) {
            grid = document.createElement('div');
            grid.id = 'debug-grid';
            grid.className = 'fixed inset-0 pointer-events-none z-50';
            grid.style.cssText = `
                background-image: 
                    linear-gradient(rgba(56, 189, 248, 0.1) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(56, 189, 248, 0.1) 1px, transparent 1px);
                background-size: 20px 20px;
                display: none;
            `;
            document.body.appendChild(grid);
        }
        grid.style.display = grid.style.display === 'none' ? 'block' : 'none';
    }
}