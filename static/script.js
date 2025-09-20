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
    setupSelectFilters(document.getElementById('newEventForm'));
    setupSelectFilters(document.getElementById('editEventForm'));
    setupConflictChecker(document.getElementById('newEventForm'));
    setupConflictChecker(document.getElementById('editEventForm'));
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

    locationSelect.addEventListener('change', () => {
        fetchSummary(locationSelect.value);
        if (typeof form.__triggerConflictCheck === 'function') {
            form.__triggerConflictCheck();
        }
    });

    if (locationSelect.value) {
        fetchSummary(locationSelect.value);
        if (typeof form.__triggerConflictCheck === 'function') {
            form.__triggerConflictCheck();
        }
    } else {
        hideSummary();
    }
}

function setupConflictChecker(form) {
    if (!form) return;

    const locationSelect = form.querySelector('#location_id');
    const startInput = form.querySelector('#event_date');
    const endInput = form.querySelector('#end_date');
    const equipmentChecks = form.querySelectorAll('.equipment-check');
    const conflictAlert = form.querySelector('#conflictAlerts');
    if (!startInput || !conflictAlert) return;

    const alertBody = conflictAlert.querySelector('.conflict-alert-body');
    const eventIdField = form.querySelector('#event_id_field');
    const csrfField = form.querySelector('input[name="csrf_token"]');

    const hideConflicts = () => {
        conflictAlert.classList.add('d-none');
        alertBody.innerHTML = '';
    };

    const renderConflicts = (conflicts) => {
        if (!conflicts || !conflicts.length) {
            hideConflicts();
            return;
        }

        const grouped = new Map();
        conflicts.forEach(conflict => {
            const key = conflict.conflict_event_id;
            if (!grouped.has(key)) {
                grouped.set(key, { event: conflict, equipment: [], hasLocation: false });
            }
            const entry = grouped.get(key);
            if (conflict.conflict_type === 'equipment') {
                entry.equipment.push(conflict.equipment_name || `Equipment #${conflict.equipment_id}`);
            }
            if (conflict.conflict_type === 'location') {
                entry.hasLocation = true;
            }
        });

        const items = Array.from(grouped.values()).map(({ event, equipment, hasLocation }) => {
            const details = [];
            if (equipment.length) {
                details.push(`<strong>Equipment:</strong> ${equipment.join(', ')}`);
            }
            if (hasLocation) {
                details.push('<strong>Location:</strong> Same venue booked');
            }
            const eventLink = event.conflict_event_id ? `<a href="/events/${event.conflict_event_id}" class="text-white text-decoration-underline" target="_blank">View event</a>` : '';
            return `
                <li class="mb-2">
                    <div><strong>${event.conflict_event_name || 'Event #' + event.conflict_event_id}</strong> &mdash; ${event.conflict_event_date || 'Date N/A'}</div>
                    <div>${details.join(' · ')}</div>
                    ${eventLink}
                </li>`;
        });

        alertBody.innerHTML = `<ul class="mb-0 ps-3">${items.join('')}</ul>`;
        conflictAlert.classList.remove('d-none');
    };

    const fetchConflicts = async () => {
        const startDate = startInput.value ? startInput.value.trim() : '';
        if (!startDate) {
            hideConflicts();
            return;
        }

        const payload = {
            event_id: eventIdField && eventIdField.value ? parseInt(eventIdField.value, 10) : 0,
            start_date: startDate,
            end_date: endInput && endInput.value ? endInput.value.trim() : '',
            location_id: locationSelect && locationSelect.value ? parseInt(locationSelect.value, 10) : null,
            equipment_ids: Array.from(form.querySelectorAll('.equipment-check:checked')).map(cb => parseInt(cb.value, 10))
        };

        try {
            const headers = {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            };
            if (csrfField && csrfField.value) {
                headers['X-CSRFToken'] = csrfField.value;
            }

            const response = await fetch('/api/events/check_conflicts', {
                method: 'POST',
                headers,
                body: JSON.stringify(payload)
            });

            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.message || 'Unable to check conflicts');
            }

            renderConflicts(data.conflicts || []);
        } catch (err) {
            alertBody.innerHTML = `<div class="text-danger"><i class="fas fa-exclamation-circle me-2"></i>${err.message}</div>`;
            conflictAlert.classList.remove('d-none');
        }
    };

    const debounce = (fn, delay = 400) => {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(null, args), delay);
        };
    };

    const debouncedFetch = debounce(fetchConflicts, 300);

    if (startInput) startInput.addEventListener('change', debouncedFetch);
    if (endInput) endInput.addEventListener('change', debouncedFetch);
    if (locationSelect) locationSelect.addEventListener('change', debouncedFetch);
    if (equipmentChecks.length) {
        equipmentChecks.forEach(cb => cb.addEventListener('change', debouncedFetch));
    }

    form.__triggerConflictCheck = fetchConflicts;
    fetchConflicts();
}

function setupSelectFilters(form) {
    if (!form) return;

    const filterInputs = form.querySelectorAll('.select-filter');
    filterInputs.forEach(input => {
        const targetId = input.getAttribute('data-target');
        if (!targetId) return;
        const select = form.querySelector(`#${targetId}`);
        if (!select) return;

        const options = Array.from(select.options);
        if (!select.dataset.initialIndex) {
            select.dataset.initialIndex = select.selectedIndex;
        }

        input.addEventListener('input', () => {
            const term = input.value.trim().toLowerCase();

            options.forEach(option => {
                if (!option.value) {
                    option.hidden = false;
                    return;
                }
                const match = option.text.toLowerCase().includes(term);
                option.hidden = Boolean(term) && !match;
            });

            if (!term) {
                const initialIndex = parseInt(select.dataset.initialIndex, 10);
                if (!Number.isNaN(initialIndex)) {
                    select.selectedIndex = initialIndex;
                }
                select.dispatchEvent(new Event('change', { bubbles: true }));
                return;
            }

            const firstVisible = options.find(option => !option.hidden && option.value);
            if (firstVisible) {
                select.value = firstVisible.value;
                select.dispatchEvent(new Event('change', { bubbles: true }));
            }
        });
    });
}

// Helper function to format time (HH:MM)
function formatTime(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    
    return `${hours}:${minutes}`;
}
