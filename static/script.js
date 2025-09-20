// JavaScript for QCS Event Management Application

document.addEventListener('DOMContentLoaded', function() {
    // Apply client colors to badges
    applyClientColors();
    
    // Calendar initialization moved to dedicated calendar.js
    
    // Setup event listeners
    setupEventListeners();
});

// Apply colors to client badges based on data-color attribute
function applyClientColors() {
    const clientBadges = document.querySelectorAll('.client-badge');
    
    clientBadges.forEach(badge => {
        const color = badge.getAttribute('data-color');
        if (color) {
            badge.style.backgroundColor = color;
        }
    });
}

// Note: initializeCalendar function removed - now using the dedicated calendar.js implementation

// Setup various event listeners
function setupEventListeners() {
    // Delete confirmation
    const deleteButtons = document.querySelectorAll('.delete-event-btn');
    
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this event?')) {
                e.preventDefault();
            }
        });
    });
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-important)');
    
    alerts.forEach(alert => {
        setTimeout(() => {
            const closeButton = alert.querySelector('.btn-close');
            if (closeButton) {
                closeButton.click();
            }
        }, 5000);
    });
    
    // Toggle invoice details
    const toggleButtons = document.querySelectorAll('.toggle-details-btn');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                if (targetElement.classList.contains('d-none')) {
                    targetElement.classList.remove('d-none');
                    this.innerHTML = '<i class="fas fa-chevron-up"></i> Hide Details';
                } else {
                    targetElement.classList.add('d-none');
                    this.innerHTML = '<i class="fas fa-chevron-down"></i> Show Details';
                }
            }
        });
    });
    
    setupEventFormValidation(document.getElementById('newEventForm'));
    setupEventFormValidation(document.getElementById('editEventForm'));
    setupLocationInsights(document.getElementById('newEventForm'));
    setupLocationInsights(document.getElementById('editEventForm'));
}

// Helper function to format date (YYYY-MM-DD)
function formatDate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    
    return `${year}-${month}-${day}`;
}

function setupEventFormValidation(form) {
    if (!form) return;

    const requiredFields = [
        { field: form.querySelector('#event_name'), message: 'Event title is required.' },
        { field: form.querySelector('#client_id'), message: 'Client selection is required.' },
        { field: form.querySelector('#event_date'), message: 'Start date is required.' },
    ];

    const removeInvalid = (field) => {
        if (!field) return;
        field.classList.remove('is-invalid');
    };

    requiredFields.forEach(item => {
        if (!item.field) return;
        const listenerEvent = item.field.tagName === 'SELECT' ? 'change' : 'input';
        item.field.addEventListener(listenerEvent, () => removeInvalid(item.field));
    });

    form.addEventListener('submit', (e) => {
        const messages = [];

        requiredFields.forEach(item => {
            if (!item.field) return;
            const value = item.field.value ? item.field.value.trim() : '';
            if (!value) {
                item.field.classList.add('is-invalid');
                messages.push(item.message);
            }
        });

        if (messages.length) {
            e.preventDefault();
            showFormAlert(form, messages);
        }
    });
}

function showFormAlert(form, messages) {
    if (!form) return;

    const existingAlert = form.querySelector('.form-validation-alert');
    if (existingAlert) {
        existingAlert.remove();
    }

    const alertBox = document.createElement('div');
    alertBox.className = 'alert alert-danger alert-dismissible fade show mt-3 form-validation-alert';
    alertBox.innerHTML = `
        <strong>Please review the following:</strong>
        <ul class="mb-0">${messages.map(msg => `<li>${msg}</li>`).join('')}</ul>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

    form.insertBefore(alertBox, form.firstChild);
}

function setupLocationInsights(form) {
    if (!form) return;

    const locationSelect = form.querySelector('#location_id');
    const summaryCard = form.querySelector('#locationSummary');
    const eventIdField = form.querySelector('#event_id_field');

    if (!locationSelect || !summaryCard) return;

    const cardBody = summaryCard.querySelector('.card-body');

    const renderSummary = (data) => {
        if (!data || !data.success) {
            cardBody.innerHTML = `<div class="text-danger"><i class="fas fa-exclamation-circle me-2"></i>${data && data.message ? data.message : 'Unable to load location details.'}</div>`;
            summaryCard.classList.remove('d-none');
            return;
        }

        const location = data.location || {};
        const upcoming = data.upcoming_events || [];

        const addressParts = [location.address, [location.city, location.state].filter(Boolean).join(', '), location.zip_code]
            .filter(Boolean)
            .join('<br>');

        const contactItems = [];
        if (location.phone) contactItems.push(`<i class="fas fa-phone me-2"></i>${location.phone}`);
        if (location.email) contactItems.push(`<i class="fas fa-envelope me-2"></i><a href="mailto:${location.email}">${location.email}</a>`);
        if (location.website) contactItems.push(`<i class="fas fa-globe me-2"></i><a href="${location.website}" target="_blank" rel="noopener">Website</a>`);

        const eventsMarkup = upcoming.length
            ? `<ul class="list-group list-group-flush">
                    ${upcoming.map(ev => `
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>${ev.event_name}</strong><br>
                                <small class="text-muted">${ev.event_date}${ev.drop_off_time ? ' · ' + ev.drop_off_time : ''}</small>
                            </div>
                            <span class="badge bg-secondary text-capitalize">${ev.status}</span>
                        </li>
                    `).join('')}
               </ul>`
            : '<p class="text-success mb-0"><i class="fas fa-check-circle me-2"></i>No upcoming events at this location.</p>';

        cardBody.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <h6 class="fw-bold mb-2"><i class="fas fa-map-marker-alt me-2"></i>${location.name || 'Selected Location'}</h6>
                    <p class="mb-2">${addressParts || '<span class="text-muted">No address on file.</span>'}</p>
                    ${contactItems.length ? `<p class="mb-0">${contactItems.join('<br>')}</p>` : ''}
                    ${location.notes ? `<p class="mt-2 mb-0"><i class="fas fa-sticky-note me-2"></i>${location.notes}</p>` : ''}
                </div>
                <div class="col-md-6">
                    <h6 class="fw-bold mb-2"><i class="fas fa-calendar-alt me-2"></i>Upcoming Events</h6>
                    ${eventsMarkup}
                </div>
            </div>
        `;

        summaryCard.classList.remove('d-none');
    };

    const showLoading = () => {
        summaryCard.classList.remove('d-none');
        cardBody.innerHTML = '<div class="text-muted"><i class="fas fa-spinner fa-spin me-2"></i>Checking location availability...</div>';
    };

    const hideSummary = () => {
        summaryCard.classList.add('d-none');
        cardBody.innerHTML = '<p class="text-muted mb-0">Select a location to view address details and upcoming events scheduled there.</p>';
    };

    const fetchSummary = async (locationId) => {
        if (!locationId) {
            hideSummary();
            return;
        }

        showLoading();

        try {
            let url = `/api/locations/${locationId}/summary`;
            if (eventIdField && eventIdField.value) {
                url += `?exclude_event_id=${eventIdField.value}`;
            }

            const response = await fetch(url, {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || 'Unable to load location details.');
            }

            renderSummary(data);
        } catch (err) {
            cardBody.innerHTML = `<div class="text-danger"><i class="fas fa-exclamation-circle me-2"></i>${err.message}</div>`;
        }
    };

    locationSelect.addEventListener('change', () => fetchSummary(locationSelect.value));

    if (locationSelect.value) {
        fetchSummary(locationSelect.value);
    } else {
        hideSummary();
    }
}

// Helper function to format time (HH:MM)
function formatTime(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    
    return `${hours}:${minutes}`;
}
