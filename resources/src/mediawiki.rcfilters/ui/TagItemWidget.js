/**
 * Extend OOUI's TagItemWidget to also display a popup on hover.
 *
 * @class mw.rcfilters.ui.TagItemWidget
 * @ignore
 * @extends OO.ui.TagItemWidget
 * @mixes OO.ui.mixin.PopupElement
 *
 * @param {mw.rcfilters.Controller} controller
 * @param {mw.rcfilters.dm.FiltersViewModel} filtersViewModel
 * @param {mw.rcfilters.dm.FilterItem|null} invertModel
 * @param {mw.rcfilters.dm.FilterItem} itemModel Item model
 * @param {Object} config Configuration object
 * @param {jQuery} [config.$overlay] A jQuery object serving as overlay for popups
 */
const TagItemWidget = function MwRcfiltersUiTagItemWidget(
	controller, filtersViewModel, invertModel, itemModel, config
) {
	// Configuration initialization
	config = config || {};

	this.controller = controller;
	this.invertModel = invertModel;
	this.filtersViewModel = filtersViewModel;
	this.itemModel = itemModel;
	this.selected = false;

	TagItemWidget.super.call( this, Object.assign( {
		data: this.itemModel.getName()
	}, config ) );

	this.$overlay = config.$overlay || this.$element;
	this.popupLabel = new OO.ui.LabelWidget();

	// Mixin constructors
	OO.ui.mixin.PopupElement.call( this, Object.assign( {
		popup: {
			padded: false,
			align: 'center',
			position: 'above',
			$content: $( '<div>' )
				.addClass( 'mw-rcfilters-ui-tagItemWidget-popup-content' )
				.append( this.popupLabel.$element ),
			$floatableContainer: this.$element,
			classes: [ 'mw-rcfilters-ui-tagItemWidget-popup' ]
		}
	}, config ) );

	this.popupTimeoutShow = null;
	this.popupTimeoutHide = null;

	this.$highlight = $( '<div>' )
		.addClass( 'mw-rcfilters-ui-tagItemWidget-highlight' );

	// Add title attribute with the item label to 'x' button
	this.closeButton.setTitle( mw.msg( 'rcfilters-tag-remove', this.itemModel.getLabel() ) );

	// Events
	this.filtersViewModel.connect( this, { highlightChange: 'updateUiBasedOnState' } );
	if ( this.invertModel ) {
		this.invertModel.connect( this, { update: 'updateUiBasedOnState' } );
	}
	this.itemModel.connect( this, { update: 'updateUiBasedOnState' } );

	// Initialization
	this.$overlay.append( this.popup.$element );
	this.$element
		.addClass( 'mw-rcfilters-ui-tagItemWidget' )
		.prepend( this.$highlight )
		.attr( 'aria-haspopup', 'true' )
		.on( 'mouseenter', this.onMouseEnter.bind( this ) )
		.on( 'mouseleave', this.onMouseLeave.bind( this ) );

	this.updateUiBasedOnState();
};

/* Initialization */

OO.inheritClass( TagItemWidget, OO.ui.TagItemWidget );
OO.mixinClass( TagItemWidget, OO.ui.mixin.PopupElement );

/* Methods */

/**
 * Respond to model update event
 */
TagItemWidget.prototype.updateUiBasedOnState = function () {
	// Update label if needed
	const labelMsg = this.itemModel.getLabelMessageKey( this.invertModel && this.invertModel.isSelected() );
	if ( labelMsg ) {
		this.setLabel(
			$( '<bdi>' ).append(
				// eslint-disable-next-line mediawiki/msg-doc
				mw.message( labelMsg, mw.html.escape( this.itemModel.getLabel() ) ).parseDom()
			)
		);
	} else {
		this.setLabel(
			$( '<bdi>' ).text(
				this.itemModel.getLabel()
			)
		);
	}

	this.setCurrentMuteState();
	this.setHighlightColor();
};

/**
 * Set the current highlight color for this item
 */
TagItemWidget.prototype.setHighlightColor = function () {
	const selectedColor = this.filtersViewModel.isHighlightEnabled() && this.itemModel.isHighlighted ?
		this.itemModel.getHighlightColor() :
		null;

	this.$highlight
		.attr( 'data-color', selectedColor )
		.toggleClass(
			'mw-rcfilters-ui-tagItemWidget-highlight-highlighted',
			!!selectedColor
		);
};

/**
 * Set the current mute state for this item
 */
TagItemWidget.prototype.setCurrentMuteState = function () {};

/**
 * Respond to mouse enter event
 */
TagItemWidget.prototype.onMouseEnter = function () {
	const labelText = this.itemModel.getStateMessage();

	if ( labelText ) {
		this.popupLabel.setLabel( labelText );

		// Set timeout for the popup to show
		this.popupTimeoutShow = setTimeout( () => {
			this.popup.toggle( true );
		}, 500 );

		// Cancel the hide timeout
		clearTimeout( this.popupTimeoutHide );
		this.popupTimeoutHide = null;
	}
};

/**
 * Respond to mouse leave event
 */
TagItemWidget.prototype.onMouseLeave = function () {
	this.popupTimeoutHide = setTimeout( () => {
		this.popup.toggle( false );
	}, 250 );

	// Clear the show timeout
	clearTimeout( this.popupTimeoutShow );
	this.popupTimeoutShow = null;
};

/**
 * Set selected state on this widget
 *
 * @param {boolean} [isSelected] Widget is selected
 */
TagItemWidget.prototype.toggleSelected = function ( isSelected ) {
	isSelected = isSelected !== undefined ? isSelected : !this.selected;

	if ( this.selected !== isSelected ) {
		this.selected = isSelected;

		this.$element.toggleClass( 'mw-rcfilters-ui-tagItemWidget-selected', this.selected );
	}
};

/**
 * Get the selected state of this widget
 *
 * @return {boolean} Tag is selected
 */
TagItemWidget.prototype.isSelected = function () {
	return this.selected;
};

/**
 * Get item name
 *
 * @return {string} Filter name
 */
TagItemWidget.prototype.getName = function () {
	return this.itemModel.getName();
};

/**
 * Get item model
 *
 * @return {string} Filter model
 */
TagItemWidget.prototype.getModel = function () {
	return this.itemModel;
};

/**
 * Get item view
 *
 * @return {string} Filter view
 */
TagItemWidget.prototype.getView = function () {
	return this.itemModel.getGroupModel().getView();
};

/**
 * Remove and destroy external elements of this widget
 */
TagItemWidget.prototype.destroy = function () {
	// Destroy the popup
	this.popup.$element.detach();

	// Disconnect events
	this.itemModel.disconnect( this );
	this.closeButton.disconnect( this );
};

module.exports = TagItemWidget;
