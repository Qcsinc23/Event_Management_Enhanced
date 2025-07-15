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
    
    // New event form validation
    const newEventForm = document.getElementById('newEventForm');
    
    if (newEventForm) {
        newEventForm.addEventListener('submit', function(e) {
            const title = document.getElementById('title').value;
            const client = document.getElementById('client_id').value;
            const eventDate = document.getElementById('event_date').value;
            
            if (!title || !client || !eventDate) {
                e.preventDefault();
                
                // Show validation message
                const alertBox = document.createElement('div');
                alertBox.className = 'alert alert-danger alert-dismissible fade show mt-3';
                alertBox.innerHTML = `
                    <strong>Error!</strong> Please fill in all required fields.
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                `;
                
                // Insert alert at the top of the form
                newEventForm.insertBefore(alertBox, newEventForm.firstChild);
            }
        });
    }
}

// Helper function to format date (YYYY-MM-DD)
function formatDate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    
    return `${year}-${month}-${day}`;
}

// Helper function to format time (HH:MM)
function formatTime(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    
    return `${hours}:${minutes}`;
}

// Form Validation Class
class FormValidator {
    constructor(formId) {
        this.form = document.getElementById(formId);
        if (this.form) {
            this.form.setAttribute('novalidate', '');
            this.form.addEventListener('submit', this.handleSubmit.bind(this));
        }
    }

    handleSubmit(event) {
        if (!this.form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
            this.displayErrors();
        }
        this.form.classList.add('was-validated');
    }

    displayErrors() {
        this.form.querySelectorAll('.form-control:invalid, .form-select:invalid').forEach(input => {
            this.addError(input, input.validationMessage);
        });
    }

    addError(input, message) {
        this.removeError(input);
        const parent = input.parentElement;
        const error = document.createElement('div');
        error.className = 'invalid-feedback';
        error.textContent = message;
        parent.appendChild(error);
    }

    removeError(input) {
        const parent = input.parentElement;
        const error = parent.querySelector('.invalid-feedback');
        if (error) {
            parent.removeChild(error);
        }
    }
}

// Enhanced Search Functionality
class SearchManager {
    constructor() {
        this.searchInput = document.getElementById('globalSearch');
        this.mobileSearchInput = document.getElementById('mobileSearchInput');
        this.searchSuggestions = document.getElementById('searchSuggestions');
        this.searchHistory = JSON.parse(localStorage.getItem('searchHistory')) || [];
        this.debounceTimer = null;
        this.currentController = null;
        
        this.init();
    }

    init() {
        if (this.searchInput) {
            this.searchInput.addEventListener('input', this.handleSearch.bind(this));
            this.searchInput.addEventListener('focus', this.handleFocus.bind(this));
            this.searchInput.addEventListener('keydown', this.handleKeydown.bind(this));
        }
        
        if (this.mobileSearchInput) {
            this.mobileSearchInput.addEventListener('input', this.handleSearch.bind(this));
            this.mobileSearchInput.addEventListener('focus', this.handleFocus.bind(this));
            this.mobileSearchInput.addEventListener('keydown', this.handleKeydown.bind(this));
        }
        
        document.addEventListener('click', this.handleOutsideClick.bind(this));
    }

    handleSearch(event) {
        const query = event.target.value.trim();
        
        // Clear previous debounce
        if (this.debounceTimer) {
            clearTimeout(this.debounceTimer);
        }
        
        // Debounce search
        this.debounceTimer = setTimeout(() => {
            this.performSearch(query);
        }, 300);
    }

    async performSearch(query) {
        if (query.length < 2) {
            this.hideSuggestions();
            return;
        }

        try {
            // Cancel previous request
            if (this.currentController) {
                this.currentController.abort();
            }

            this.currentController = new AbortController();
            
            const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`, {
                signal: this.currentController.signal
            });

            if (!response.ok) {
                throw new Error('Search failed');
            }

            const results = await response.json();
            this.displaySuggestions(results, query);
            
        } catch (error) {
            if (error.name !== 'AbortError') {
                console.error('Search error:', error);
                this.showSearchError();
            }
        }
    }

    displaySuggestions(results, query) {
        if (!results || results.length === 0) {
            this.showNoResults(query);
            return;
        }

        const suggestionsHtml = results.map(result => {
            const icon = this.getResultIcon(result.type);
            return `
                <div class="search-suggestion-item" data-type="${result.type}" data-id="${result.id}">
                    <div class="search-suggestion-icon">
                        <i class="${icon}"></i>
                    </div>
                    <div class="search-suggestion-content">
                        <div class="search-suggestion-title">${this.highlightQuery(result.title, query)}</div>
                        <div class="search-suggestion-meta">${result.type} • ${result.meta}</div>
                    </div>
                </div>
            `;
        }).join('');

        this.searchSuggestions.innerHTML = suggestionsHtml;
        this.searchSuggestions.classList.add('show');
        
        // Add click handlers
        this.searchSuggestions.querySelectorAll('.search-suggestion-item').forEach(item => {
            item.addEventListener('click', this.handleSuggestionClick.bind(this));
        });
    }

    showNoResults(query) {
        this.searchSuggestions.innerHTML = `
            <div class="search-no-results">
                <div class="search-no-results-icon">
                    <i class="fas fa-search"></i>
                </div>
                <div class="search-no-results-text">No results found for "${query}"</div>
            </div>
        `;
        this.searchSuggestions.classList.add('show');
    }

    showSearchError() {
        this.searchSuggestions.innerHTML = `
            <div class="search-error">
                <div class="search-error-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="search-error-text">Search temporarily unavailable</div>
            </div>
        `;
        this.searchSuggestions.classList.add('show');
    }

    getResultIcon(type) {
        const icons = {
            'event': 'fas fa-calendar-alt',
            'client': 'fas fa-user-tie',
            'equipment': 'fas fa-cogs',
            'location': 'fas fa-map-marker-alt',
            'invoice': 'fas fa-file-invoice'
        };
        return icons[type] || 'fas fa-file';
    }

    highlightQuery(text, query) {
        const regex = new RegExp(`(${query})`, 'gi');
        return text.replace(regex, '<mark>$1</mark>');
    }

    handleSuggestionClick(event) {
        const item = event.currentTarget;
        const type = item.dataset.type;
        const id = item.dataset.id;
        const title = item.querySelector('.search-suggestion-title').textContent;
        
        this.addToHistory(title, type, id);
        this.navigateToResult(type, id);
        this.hideSuggestions();
    }

    addToHistory(title, type, id) {
        const entry = { title, type, id, timestamp: Date.now() };
        this.searchHistory.unshift(entry);
        this.searchHistory = this.searchHistory.slice(0, 10); // Keep only last 10
        localStorage.setItem('searchHistory', JSON.stringify(this.searchHistory));
    }

    navigateToResult(type, id) {
        const routes = {
            'event': `/events/${id}`,
            'client': `/clients/${id}`,
            'equipment': `/equipment/${id}`,
            'location': `/locations/${id}`,
            'invoice': `/invoices/${id}`
        };
        
        if (routes[type]) {
            window.location.href = routes[type];
        }
    }

    handleFocus(event) {
        if (event.target.value.trim().length > 0) {
            this.searchSuggestions.classList.add('show');
        } else {
            this.showSearchHistory();
        }
    }

    showSearchHistory() {
        if (this.searchHistory.length === 0) {
            this.hideSuggestions();
            return;
        }

        const historyHtml = this.searchHistory.map(entry => {
            const icon = this.getResultIcon(entry.type);
            return `
                <div class="search-history-item" data-type="${entry.type}" data-id="${entry.id}">
                    <div class="search-suggestion-icon">
                        <i class="${icon}"></i>
                    </div>
                    <div class="search-suggestion-content">
                        <div class="search-suggestion-title">${entry.title}</div>
                        <div class="search-suggestion-meta">${entry.type} • Recent</div>
                    </div>
                    <button class="search-history-remove" data-title="${entry.title}">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
        }).join('');

        this.searchSuggestions.innerHTML = `
            <div class="search-history-header">Recent Searches</div>
            ${historyHtml}
            <div class="search-history-footer">
                <button class="search-history-clear">Clear All</button>
            </div>
        `;
        this.searchSuggestions.classList.add('show');
        
        // Add event listeners
        this.searchSuggestions.querySelectorAll('.search-history-item').forEach(item => {
            item.addEventListener('click', this.handleSuggestionClick.bind(this));
        });
        
        this.searchSuggestions.querySelectorAll('.search-history-remove').forEach(btn => {
            btn.addEventListener('click', this.handleHistoryRemove.bind(this));
        });
        
        const clearBtn = this.searchSuggestions.querySelector('.search-history-clear');
        if (clearBtn) {
            clearBtn.addEventListener('click', this.clearHistory.bind(this));
        }
    }

    handleHistoryRemove(event) {
        event.stopPropagation();
        const title = event.target.closest('.search-history-remove').dataset.title;
        this.searchHistory = this.searchHistory.filter(entry => entry.title !== title);
        localStorage.setItem('searchHistory', JSON.stringify(this.searchHistory));
        this.showSearchHistory();
    }

    clearHistory() {
        this.searchHistory = [];
        localStorage.removeItem('searchHistory');
        this.hideSuggestions();
    }

    handleKeydown(event) {
        if (event.key === 'Escape') {
            this.hideSuggestions();
            event.target.blur();
        }
    }

    handleOutsideClick(event) {
        if (!event.target.closest('.search-box') && !event.target.closest('.mobile-search-container')) {
            this.hideSuggestions();
        }
    }

    hideSuggestions() {
        this.searchSuggestions.classList.remove('show');
    }
}

// Global Error Handler
class ErrorHandler {
    constructor() {
        this.init();
    }

    init() {
        // Handle uncaught errors
        window.addEventListener('error', this.handleError.bind(this));
        window.addEventListener('unhandledrejection', this.handlePromiseRejection.bind(this));
        
        // Handle network errors
        this.setupNetworkMonitoring();
    }

    handleError(event) {
        console.error('Global error:', event.error);
        this.showErrorNotification('An unexpected error occurred. Please refresh the page.');
    }

    handlePromiseRejection(event) {
        console.error('Unhandled promise rejection:', event.reason);
        this.showErrorNotification('A network error occurred. Please check your connection.');
    }

    setupNetworkMonitoring() {
        window.addEventListener('online', () => {
            this.showSuccessNotification('Connection restored');
        });

        window.addEventListener('offline', () => {
            this.showErrorNotification('No internet connection. Some features may not work.');
        });
    }

    showErrorNotification(message) {
        this.showNotification(message, 'error');
    }

    showSuccessNotification(message) {
        this.showNotification(message, 'success');
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `error-notification error-notification-${type}`;
        notification.innerHTML = `
            <div class="error-notification-content">
                <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'check-circle'}"></i>
                <span>${message}</span>
            </div>
            <button class="error-notification-close">
                <i class="fas fa-times"></i>
            </button>
        `;

        document.body.appendChild(notification);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            this.removeNotification(notification);
        }, 5000);

        // Manual dismiss
        notification.querySelector('.error-notification-close').addEventListener('click', () => {
            this.removeNotification(notification);
        });

        // Show notification
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
    }

    removeNotification(notification) {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }
}

// Keyboard Navigation Handler
class KeyboardNavigationHandler {
    constructor() {
        this.init();
    }

    init() {
        document.addEventListener('keydown', this.handleKeydown.bind(this));
        this.setupFocusTrapping();
    }

    handleKeydown(event) {
        // Handle global keyboard shortcuts
        if (event.ctrlKey || event.metaKey) {
            switch (event.key) {
                case 'k':
                    event.preventDefault();
                    this.focusSearch();
                    break;
                case 'n':
                    event.preventDefault();
                    this.goToNewEvent();
                    break;
                case 'h':
                    event.preventDefault();
                    this.goToHome();
                    break;
            }
        }

        // Handle escape key
        if (event.key === 'Escape') {
            this.handleEscape();
        }
    }

    focusSearch() {
        const searchInput = document.getElementById('globalSearch');
        if (searchInput) {
            searchInput.focus();
        }
    }

    goToNewEvent() {
        if (typeof newEventUrl !== 'undefined') {
            window.location.href = newEventUrl;
        }
    }

    goToHome() {
        window.location.href = '/';
    }

    handleEscape() {
        // Close any open modals or panels
        const openModals = document.querySelectorAll('.modal.show');
        openModals.forEach(modal => {
            const modalInstance = bootstrap.Modal.getInstance(modal);
            if (modalInstance) {
                modalInstance.hide();
            }
        });

        // Close notifications panel
        const notificationsPanel = document.getElementById('notificationsPanel');
        if (notificationsPanel && notificationsPanel.classList.contains('show')) {
            notificationsPanel.classList.remove('show');
        }

        // Close search suggestions
        const searchSuggestions = document.getElementById('searchSuggestions');
        if (searchSuggestions && searchSuggestions.classList.contains('show')) {
            searchSuggestions.classList.remove('show');
        }
    }

    setupFocusTrapping() {
        // Add focus trapping for modals and panels
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.addEventListener('shown.bs.modal', () => {
                this.trapFocus(modal);
            });
        });
    }

    trapFocus(container) {
        const focusableElements = container.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        
        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        container.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    if (document.activeElement === firstElement) {
                        lastElement.focus();
                        e.preventDefault();
                    }
                } else {
                    if (document.activeElement === lastElement) {
                        firstElement.focus();
                        e.preventDefault();
                    }
                }
            }
        });

        // Focus first element
        firstElement.focus();
    }
}

// === Phase 3: Advanced Features ===

// Drag and Drop Manager
class DragDropManager {
    constructor() {
        this.draggedElement = null;
        this.dropZones = [];
        this.init();
    }

    init() {
        this.setupDraggableElements();
        this.setupDropZones();
    }

    setupDraggableElements() {
        const draggableElements = document.querySelectorAll('[data-draggable="true"]');
        draggableElements.forEach(element => {
            element.setAttribute('draggable', 'true');
            element.addEventListener('dragstart', this.handleDragStart.bind(this));
            element.addEventListener('dragend', this.handleDragEnd.bind(this));
        });
    }

    setupDropZones() {
        const dropZones = document.querySelectorAll('[data-drop-zone="true"]');
        dropZones.forEach(zone => {
            zone.addEventListener('dragover', this.handleDragOver.bind(this));
            zone.addEventListener('dragenter', this.handleDragEnter.bind(this));
            zone.addEventListener('dragleave', this.handleDragLeave.bind(this));
            zone.addEventListener('drop', this.handleDrop.bind(this));
            this.dropZones.push(zone);
        });
    }

    handleDragStart(event) {
        this.draggedElement = event.target;
        event.target.classList.add('dragging');
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/html', event.target.outerHTML);
        event.dataTransfer.setData('text/plain', event.target.dataset.id || '');
    }

    handleDragEnd(event) {
        event.target.classList.remove('dragging');
        this.dropZones.forEach(zone => zone.classList.remove('drag-over'));
        this.draggedElement = null;
    }

    handleDragOver(event) {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
    }

    handleDragEnter(event) {
        event.preventDefault();
        event.target.classList.add('drag-over');
    }

    handleDragLeave(event) {
        event.target.classList.remove('drag-over');
    }

    handleDrop(event) {
        event.preventDefault();
        event.target.classList.remove('drag-over');
        
        const draggedId = event.dataTransfer.getData('text/plain');
        const dropZoneId = event.target.dataset.dropZoneId;
        
        if (draggedId && dropZoneId) {
            this.handleDropAction(draggedId, dropZoneId);
        }
    }

    handleDropAction(draggedId, dropZoneId) {
        // Emit custom event for drop action
        const dropEvent = new CustomEvent('itemDropped', {
            detail: { draggedId, dropZoneId }
        });
        document.dispatchEvent(dropEvent);
    }
}

// Inline Editor
class InlineEditor {
    constructor() {
        this.activeEditor = null;
        this.init();
    }

    init() {
        this.setupEditableElements();
    }

    setupEditableElements() {
        const editableElements = document.querySelectorAll('[data-editable="true"]');
        editableElements.forEach(element => {
            element.addEventListener('dblclick', this.startEdit.bind(this));
        });
    }

    startEdit(event) {
        const element = event.target;
        if (this.activeEditor) {
            this.cancelEdit();
        }

        this.activeEditor = element;
        const originalValue = element.textContent;
        const inputType = element.dataset.inputType || 'text';
        
        let input;
        if (inputType === 'textarea') {
            input = document.createElement('textarea');
            input.rows = 3;
        } else {
            input = document.createElement('input');
            input.type = inputType;
        }

        input.value = originalValue;
        input.className = 'inline-editor-input';
        input.addEventListener('blur', this.saveEdit.bind(this));
        input.addEventListener('keydown', this.handleKeydown.bind(this));

        element.style.display = 'none';
        element.parentNode.insertBefore(input, element);
        input.focus();
        input.select();
    }

    handleKeydown(event) {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            this.saveEdit();
        } else if (event.key === 'Escape') {
            this.cancelEdit();
        }
    }

    saveEdit() {
        if (!this.activeEditor) return;

        const input = this.activeEditor.parentNode.querySelector('.inline-editor-input');
        const newValue = input.value;
        const originalValue = this.activeEditor.textContent;

        if (newValue !== originalValue) {
            this.activeEditor.textContent = newValue;
            this.saveToServer(this.activeEditor.dataset.id, newValue);
        }

        this.cleanup();
    }

    cancelEdit() {
        this.cleanup();
    }

    cleanup() {
        if (this.activeEditor) {
            const input = this.activeEditor.parentNode.querySelector('.inline-editor-input');
            if (input) {
                input.remove();
            }
            this.activeEditor.style.display = '';
            this.activeEditor = null;
        }
    }

    async saveToServer(id, value) {
        try {
            const response = await fetch('/api/inline-edit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ id, value })
            });

            if (!response.ok) {
                throw new Error('Save failed');
            }
        } catch (error) {
            console.error('Inline edit save error:', error);
            // Revert changes if save fails
            location.reload();
        }
    }
}

// Context Menu Manager
class ContextMenuManager {
    constructor() {
        this.contextMenu = null;
        this.init();
    }

    init() {
        this.createContextMenu();
        this.setupContextMenuElements();
        document.addEventListener('click', this.hideContextMenu.bind(this));
    }

    createContextMenu() {
        this.contextMenu = document.createElement('div');
        this.contextMenu.className = 'context-menu';
        this.contextMenu.style.display = 'none';
        document.body.appendChild(this.contextMenu);
    }

    setupContextMenuElements() {
        const contextElements = document.querySelectorAll('[data-context-menu="true"]');
        contextElements.forEach(element => {
            element.addEventListener('contextmenu', this.showContextMenu.bind(this));
        });
    }

    showContextMenu(event) {
        event.preventDefault();
        const target = event.target;
        const menuItems = this.getMenuItems(target);
        
        this.contextMenu.innerHTML = menuItems.map(item => `
            <div class="context-menu-item" data-action="${item.action}">
                <i class="${item.icon}"></i>
                <span>${item.label}</span>
            </div>
        `).join('');

        this.contextMenu.style.display = 'block';
        this.contextMenu.style.left = `${event.pageX}px`;
        this.contextMenu.style.top = `${event.pageY}px`;

        // Add click handlers
        this.contextMenu.querySelectorAll('.context-menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                this.handleMenuAction(e.target.dataset.action, target);
                this.hideContextMenu();
            });
        });
    }

    getMenuItems(target) {
        const menuType = target.dataset.contextMenuType || 'default';
        
        const menus = {
            'event': [
                { action: 'edit', label: 'Edit Event', icon: 'fas fa-edit' },
                { action: 'duplicate', label: 'Duplicate', icon: 'fas fa-copy' },
                { action: 'delete', label: 'Delete', icon: 'fas fa-trash' }
            ],
            'table-row': [
                { action: 'view', label: 'View Details', icon: 'fas fa-eye' },
                { action: 'edit', label: 'Edit', icon: 'fas fa-edit' },
                { action: 'delete', label: 'Delete', icon: 'fas fa-trash' }
            ],
            'default': [
                { action: 'copy', label: 'Copy', icon: 'fas fa-copy' },
                { action: 'refresh', label: 'Refresh', icon: 'fas fa-sync' }
            ]
        };

        return menus[menuType] || menus.default;
    }

    handleMenuAction(action, target) {
        const actionEvent = new CustomEvent('contextMenuAction', {
            detail: { action, target }
        });
        document.dispatchEvent(actionEvent);
    }

    hideContextMenu() {
        if (this.contextMenu) {
            this.contextMenu.style.display = 'none';
        }
    }
}

// Bulk Operations Manager
class BulkOperationsManager {
    constructor() {
        this.selectedItems = new Set();
        this.init();
    }

    init() {
        this.setupBulkSelectors();
        this.setupBulkActions();
    }

    setupBulkSelectors() {
        const selectAllCheckbox = document.getElementById('selectAll');
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', this.handleSelectAll.bind(this));
        }

        const itemCheckboxes = document.querySelectorAll('[data-bulk-select="true"]');
        itemCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', this.handleItemSelect.bind(this));
        });
    }

    setupBulkActions() {
        const bulkActionButtons = document.querySelectorAll('[data-bulk-action="true"]');
        bulkActionButtons.forEach(button => {
            button.addEventListener('click', this.handleBulkAction.bind(this));
        });
    }

    handleSelectAll(event) {
        const isChecked = event.target.checked;
        const itemCheckboxes = document.querySelectorAll('[data-bulk-select="true"]');
        
        itemCheckboxes.forEach(checkbox => {
            checkbox.checked = isChecked;
            if (isChecked) {
                this.selectedItems.add(checkbox.value);
            } else {
                this.selectedItems.delete(checkbox.value);
            }
        });

        this.updateBulkActionBar();
    }

    handleItemSelect(event) {
        const checkbox = event.target;
        if (checkbox.checked) {
            this.selectedItems.add(checkbox.value);
        } else {
            this.selectedItems.delete(checkbox.value);
        }

        this.updateBulkActionBar();
        this.updateSelectAllState();
    }

    updateSelectAllState() {
        const selectAllCheckbox = document.getElementById('selectAll');
        const itemCheckboxes = document.querySelectorAll('[data-bulk-select="true"]');
        
        if (selectAllCheckbox && itemCheckboxes.length > 0) {
            const checkedCount = Array.from(itemCheckboxes).filter(cb => cb.checked).length;
            selectAllCheckbox.checked = checkedCount === itemCheckboxes.length;
            selectAllCheckbox.indeterminate = checkedCount > 0 && checkedCount < itemCheckboxes.length;
        }
    }

    updateBulkActionBar() {
        const bulkActionBar = document.getElementById('bulkActionBar');
        const selectedCount = this.selectedItems.size;

        if (bulkActionBar) {
            if (selectedCount > 0) {
                bulkActionBar.style.display = 'flex';
                bulkActionBar.querySelector('.selected-count').textContent = selectedCount;
            } else {
                bulkActionBar.style.display = 'none';
            }
        }
    }

    handleBulkAction(event) {
        const action = event.target.dataset.bulkAction;
        const selectedIds = Array.from(this.selectedItems);

        if (selectedIds.length === 0) {
            alert('Please select items to perform this action.');
            return;
        }

        const bulkEvent = new CustomEvent('bulkAction', {
            detail: { action, selectedIds }
        });
        document.dispatchEvent(bulkEvent);
    }
}

// Animation Manager
class AnimationManager {
    constructor() {
        this.init();
    }

    init() {
        this.setupScrollAnimations();
        this.setupPageTransitions();
    }

    setupScrollAnimations() {
        const animatedElements = document.querySelectorAll('[data-animate-on-scroll="true"]');
        
        if (animatedElements.length > 0) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        this.animateElement(entry.target);
                    }
                });
            }, { threshold: 0.1 });

            animatedElements.forEach(element => {
                observer.observe(element);
            });
        }
    }

    setupPageTransitions() {
        const links = document.querySelectorAll('a[href^="/"]');
        links.forEach(link => {
            link.addEventListener('click', this.handlePageTransition.bind(this));
        });
    }

    animateElement(element) {
        const animation = element.dataset.animation || 'fadeInUp';
        element.classList.add('animate__animated', `animate__${animation}`);
    }

    handlePageTransition(event) {
        if (event.metaKey || event.ctrlKey) return;
        
        const link = event.target.closest('a');
        if (link && link.href && !link.target) {
            event.preventDefault();
            this.transitionToPage(link.href);
        }
    }

    transitionToPage(url) {
        document.body.classList.add('page-transitioning');
        
        setTimeout(() => {
            window.location.href = url;
        }, 300);
    }
}

// Dashboard Customizer
class DashboardCustomizer {
    constructor() {
        this.widgets = [];
        this.init();
    }

    init() {
        this.loadWidgetConfig();
        this.setupDashboardControls();
        this.setupSortableWidgets();
    }

    loadWidgetConfig() {
        const config = localStorage.getItem('dashboardConfig');
        if (config) {
            this.widgets = JSON.parse(config);
            this.applyWidgetConfig();
        }
    }

    applyWidgetConfig() {
        this.widgets.forEach(widget => {
            const element = document.getElementById(widget.id);
            if (element) {
                element.style.display = widget.visible ? 'block' : 'none';
                element.style.order = widget.order;
            }
        });
    }

    setupDashboardControls() {
        const customizeBtn = document.getElementById('customizeDashboard');
        if (customizeBtn) {
            customizeBtn.addEventListener('click', this.showCustomizeModal.bind(this));
        }
    }

    setupSortableWidgets() {
        const dashboardGrid = document.getElementById('dashboardGrid');
        if (dashboardGrid && window.Sortable) {
            new Sortable(dashboardGrid, {
                animation: 150,
                ghostClass: 'sortable-ghost',
                onEnd: this.handleWidgetReorder.bind(this)
            });
        }
    }

    showCustomizeModal() {
        // Create and show widget customization modal
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Customize Dashboard</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="widget-list">
                            ${this.generateWidgetList()}
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="dashboardCustomizer.saveConfig()">Save Changes</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
    }

    generateWidgetList() {
        const widgets = document.querySelectorAll('[data-widget="true"]');
        return Array.from(widgets).map(widget => `
            <div class="widget-config-item">
                <label class="form-check-label">
                    <input type="checkbox" class="form-check-input" 
                           data-widget-id="${widget.id}" 
                           ${widget.style.display !== 'none' ? 'checked' : ''}>
                    ${widget.dataset.widgetTitle || widget.id}
                </label>
            </div>
        `).join('');
    }

    saveConfig() {
        const checkboxes = document.querySelectorAll('[data-widget-id]');
        this.widgets = Array.from(checkboxes).map((checkbox, index) => ({
            id: checkbox.dataset.widgetId,
            visible: checkbox.checked,
            order: index
        }));

        localStorage.setItem('dashboardConfig', JSON.stringify(this.widgets));
        this.applyWidgetConfig();
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
        if (modal) modal.hide();
    }

    handleWidgetReorder(event) {
        const widgets = Array.from(event.to.children);
        this.widgets = widgets.map((widget, index) => ({
            id: widget.id,
            visible: widget.style.display !== 'none',
            order: index
        }));

        localStorage.setItem('dashboardConfig', JSON.stringify(this.widgets));
    }
}

// Real-time Notification System
class NotificationSystem {
    constructor() {
        this.notifications = [];
        this.init();
    }

    init() {
        this.createNotificationContainer();
        this.setupWebSocket();
    }

    createNotificationContainer() {
        const container = document.createElement('div');
        container.id = 'notificationContainer';
        container.className = 'notification-container';
        document.body.appendChild(container);
    }

    setupWebSocket() {
        // Mock WebSocket for now - replace with actual implementation
        this.mockRealTimeUpdates();
    }

    mockRealTimeUpdates() {
        // Simulate real-time notifications
        setInterval(() => {
            if (Math.random() < 0.1) { // 10% chance every 30 seconds
                this.showNotification({
                    title: 'New Event Created',
                    message: 'A new event has been scheduled',
                    type: 'info',
                    duration: 5000
                });
            }
        }, 30000);
    }

    showNotification(notification) {
        const notificationEl = document.createElement('div');
        notificationEl.className = `notification notification-${notification.type}`;
        notificationEl.innerHTML = `
            <div class="notification-content">
                <div class="notification-title">${notification.title}</div>
                <div class="notification-message">${notification.message}</div>
            </div>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        `;

        const container = document.getElementById('notificationContainer');
        container.appendChild(notificationEl);

        // Add close handler
        notificationEl.querySelector('.notification-close').addEventListener('click', () => {
            this.removeNotification(notificationEl);
        });

        // Auto-remove after duration
        setTimeout(() => {
            this.removeNotification(notificationEl);
        }, notification.duration || 5000);

        // Animate in
        setTimeout(() => {
            notificationEl.classList.add('show');
        }, 100);
    }

    removeNotification(notificationEl) {
        notificationEl.classList.remove('show');
        setTimeout(() => {
            if (notificationEl.parentNode) {
                notificationEl.parentNode.removeChild(notificationEl);
            }
        }, 300);
    }
}

// Performance Optimizer
class PerformanceOptimizer {
    constructor() {
        this.imageObserver = null;
        this.init();
    }

    init() {
        this.setupLazyLoading();
        this.setupTablePagination();
        this.setupImageOptimization();
        this.setupCaching();
    }

    setupLazyLoading() {
        const lazyImages = document.querySelectorAll('img[data-src]');
        
        if (lazyImages.length > 0) {
            this.imageObserver = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const img = entry.target;
                        img.src = img.dataset.src;
                        img.classList.remove('lazy');
                        this.imageObserver.unobserve(img);
                    }
                });
            });

            lazyImages.forEach(img => {
                this.imageObserver.observe(img);
            });
        }
    }

    setupTablePagination() {
        const largeTables = document.querySelectorAll('table[data-paginate="true"]');
        largeTables.forEach(table => {
            this.paginateTable(table);
        });
    }

    paginateTable(table) {
        const rowsPerPage = parseInt(table.dataset.rowsPerPage) || 10;
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= rowsPerPage) return;

        let currentPage = 1;
        const totalPages = Math.ceil(rows.length / rowsPerPage);

        const showPage = (page) => {
            const start = (page - 1) * rowsPerPage;
            const end = start + rowsPerPage;
            
            rows.forEach((row, index) => {
                row.style.display = (index >= start && index < end) ? '' : 'none';
            });
        };

        const createPagination = () => {
            const pagination = document.createElement('div');
            pagination.className = 'table-pagination';
            pagination.innerHTML = `
                <button class="btn btn-sm btn-outline-primary" id="prevPage">Previous</button>
                <span class="page-info">Page ${currentPage} of ${totalPages}</span>
                <button class="btn btn-sm btn-outline-primary" id="nextPage">Next</button>
            `;

            table.parentNode.insertBefore(pagination, table.nextSibling);

            pagination.querySelector('#prevPage').addEventListener('click', () => {
                if (currentPage > 1) {
                    currentPage--;
                    showPage(currentPage);
                    updatePagination();
                }
            });

            pagination.querySelector('#nextPage').addEventListener('click', () => {
                if (currentPage < totalPages) {
                    currentPage++;
                    showPage(currentPage);
                    updatePagination();
                }
            });
        };

        const updatePagination = () => {
            const pagination = table.parentNode.querySelector('.table-pagination');
            pagination.querySelector('.page-info').textContent = `Page ${currentPage} of ${totalPages}`;
            pagination.querySelector('#prevPage').disabled = currentPage === 1;
            pagination.querySelector('#nextPage').disabled = currentPage === totalPages;
        };

        showPage(1);
        createPagination();
    }

    setupImageOptimization() {
        const images = document.querySelectorAll('img');
        images.forEach(img => {
            if (!img.dataset.src) {
                img.dataset.src = img.src;
                img.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
                img.classList.add('lazy');
            }
        });
    }

    setupCaching() {
        // Basic caching for API responses
        if ('caches' in window) {
            caches.open('qcs-cache-v1').then(cache => {
                cache.addAll([
                    '/',
                    '/static/style.css',
                    '/static/script.js'
                ]);
            });
        }
    }
}

// Enhanced Mobile Navigation with Touch Gestures
document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    // Initialize Phase 2 functionality
    const searchManager = new SearchManager();
    const errorHandler = new ErrorHandler();
    const keyboardHandler = new KeyboardNavigationHandler();

    // Initialize Phase 3 functionality
    const dragDropManager = new DragDropManager();
    const inlineEditor = new InlineEditor();
    const contextMenuManager = new ContextMenuManager();
    const bulkOperations = new BulkOperationsManager();
    const animationManager = new AnimationManager();
    const dashboardCustomizer = new DashboardCustomizer();
    const notificationSystem = new NotificationSystem();
    const performanceOptimizer = new PerformanceOptimizer();

    // Form Validation
    const formsToValidate = document.querySelectorAll('.needs-validation');
    formsToValidate.forEach(form => {
        new FormValidator(form.id);
    });

    // Mobile touch gesture support
    let touchStartX = 0;
    let touchEndX = 0;
    let touchStartY = 0;
    let touchEndY = 0;
    
    const sidebarBackdrop = document.getElementById('sidebarBackdrop');
    
    // Touch gesture detection
    function handleTouchStart(e) {
        touchStartX = e.changedTouches[0].screenX;
        touchStartY = e.changedTouches[0].screenY;
    }
    
    function handleTouchEnd(e) {
        touchEndX = e.changedTouches[0].screenX;
        touchEndY = e.changedTouches[0].screenY;
        handleSwipeGesture();
    }
    
    function handleSwipeGesture() {
        const swipeThreshold = 50;
        const swipeDistanceX = touchEndX - touchStartX;
        const swipeDistanceY = Math.abs(touchEndY - touchStartY);
        
        // Only process horizontal swipes
        if (Math.abs(swipeDistanceX) > swipeThreshold && swipeDistanceY < 100) {
            if (swipeDistanceX > 0 && touchStartX < 50) {
                // Swipe right from left edge - open sidebar
                openMobileSidebar();
            } else if (swipeDistanceX < 0 && sidebar.classList.contains('show')) {
                // Swipe left - close sidebar
                closeMobileSidebar();
            }
        }
    }
    
    // Enhanced mobile sidebar functions
    function openMobileSidebar() {
        if (sidebar && window.innerWidth <= 768) {
            sidebar.classList.add('show');
            document.body.classList.add('sidebar-open');
            if (sidebarBackdrop) {
                sidebarBackdrop.classList.add('show');
            }
        }
    }
    
    function closeMobileSidebar() {
        if (sidebar) {
            sidebar.classList.remove('show');
            document.body.classList.remove('sidebar-open');
            if (sidebarBackdrop) {
                sidebarBackdrop.classList.remove('show');
            }
        }
    }
    
    // Add touch event listeners
    document.addEventListener('touchstart', handleTouchStart, { passive: true });
    document.addEventListener('touchend', handleTouchEnd, { passive: true });
    
    // Enhanced mobile menu toggle with better responsiveness
    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            if (window.innerWidth <= 768) {
                if (sidebar.classList.contains('show')) {
                    closeMobileSidebar();
                } else {
                    openMobileSidebar();
                }
            } else {
                // Desktop behavior
                sidebar.classList.toggle('collapsed');
                document.body.classList.toggle('sidebar-collapsed');
            }
        });
    }
    
    // Prevent sidebar from closing when clicking inside
    if (sidebar) {
        sidebar.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }
    
    // Close sidebar when clicking on backdrop
    if (sidebarBackdrop) {
        sidebarBackdrop.addEventListener('click', closeMobileSidebar);
    }
    
    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', function(e) {
        if (window.innerWidth <= 768 && 
            sidebar.classList.contains('show') && 
            !sidebar.contains(e.target) && 
            e.target !== sidebarToggle) {
            closeMobileSidebar();
        }
    });
    
    // Handle window resize
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768) {
            // Remove mobile classes when switching to desktop
            closeMobileSidebar();
        }
    });
    
    // Handle escape key to close sidebar on mobile
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && window.innerWidth <= 768 && sidebar.classList.contains('show')) {
            closeMobileSidebar();
        }
    });
});
