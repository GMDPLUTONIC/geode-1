#pragma once

#include <Geode/ui/General.hpp>
#include <Geode/ui/ScrollLayer.hpp>
#include <Geode/ui/TextArea.hpp>
#include <Geode/ui/TextInput.hpp>
#include "ModItem.hpp"
#include "../sources/ModListSource.hpp"

using namespace geode::prelude;

struct ModListErrorStatus {};
struct ModListUnkProgressStatus {};
struct ModListProgressStatus {
    uint8_t percentage;
};
using ModListStatus = std::variant<ModListErrorStatus, ModListUnkProgressStatus, ModListProgressStatus>;

class ModList : public CCNode {
protected:
    ModListSource* m_source;
    size_t m_page = 0;
    ScrollLayer* m_list;
    CCMenu* m_statusContainer;
    CCLabelBMFont* m_statusTitle;
    SimpleTextArea* m_statusDetails;
    CCMenuItemSpriteExtra* m_statusDetailsBtn;
    CCNode* m_statusLoadingCircle;
    Slider* m_statusLoadingBar;
    ModListSource::PageLoadEventListener m_listener;
    CCMenuItemSpriteExtra* m_pagePrevBtn;
    CCMenuItemSpriteExtra* m_pageNextBtn;
    CCNode* m_topContainer;
    CCNode* m_searchMenu;
    CCNode* m_updateAllMenu = nullptr;
    CCMenuItemToggler* m_toggleUpdatesOnlyBtn = nullptr;
    TextArea* m_updateCountLabel = nullptr;
    TextInput* m_searchInput;
    EventListener<InvalidateCacheFilter> m_invalidateCacheListener;
    EventListener<PromiseEventFilter<std::vector<std::string>, server::ServerError>> m_checkUpdatesListener;
    bool m_bigSize = false;
    std::atomic<size_t> m_searchInputThreads = 0;

    bool init(ModListSource* src, CCSize const& size);

    void updateTopContainer();
    void onCheckUpdates(PromiseEvent<std::vector<std::string>, server::ServerError>* event);
    void onInvalidateCache(InvalidateCacheEvent* event);

    void onPromise(ModListSource::PageLoadEvent* event);
    void onPage(CCObject*);
    void onShowStatusDetails(CCObject*);
    void onFilters(CCObject*);
    void onSort(CCObject*);
    void onClearFilters(CCObject*);
    void onToggleUpdates(CCObject*);
    void onUpdateAll(CCObject*);

public:
    static ModList* create(ModListSource* src, CCSize const& size);

    size_t getPage() const;

    void reloadPage();
    void gotoPage(size_t page, bool update = false);
    void showStatus(ModListStatus status, std::string const& message, std::optional<std::string> const& details = std::nullopt);

    void updateState();
    void updateSize(bool big);
    void activateSearch(bool activate);
};