#include "DetailLayoutRegistry.h"

#include "DetailLayoutHost.h"

#include <QList>
#include <QPointer>

namespace
{
    // detailHosts：只保存弱引用；页面销毁后 QPointer 自动变空，下一次调用清理。
    QList<QPointer<ks::ui::DetailLayoutHost>>& detailHosts()
    {
        static QList<QPointer<ks::ui::DetailLayoutHost>> hosts;
        return hosts;
    }

    // currentDetailScheme：进程内唯一全局方案，默认与 AppearanceSettings 保持一致。
    ks::settings::DetailDisplayScheme& currentDetailScheme()
    {
        static ks::settings::DetailDisplayScheme scheme =
            ks::settings::DetailDisplayScheme::BottomCollapsed;
        return scheme;
    }

    // pruneDestroyedHosts：去掉已经随懒加载页面销毁的控制器弱引用。
    void pruneDestroyedHosts()
    {
        QList<QPointer<ks::ui::DetailLayoutHost>>& hosts = detailHosts();
        for (int index = hosts.size() - 1; index >= 0; --index)
        {
            if (hosts.at(index).isNull())
            {
                hosts.removeAt(index);
            }
        }
    }
}

ks::ui::DetailLayoutHost* ks::ui::DetailLayoutRegistry::registerHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget)
{
    if (tableView == nullptr || detailEditor == nullptr || ownerWidget == nullptr)
    {
        return nullptr;
    }

    pruneDestroyedHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : detailHosts())
    {
        if (!hostPointer.isNull() && hostPointer->detailEditor() == detailEditor)
        {
            hostPointer->setTableView(tableView);
            hostPointer->applyScheme(currentDetailScheme());
            return hostPointer.data();
        }
    }

    // 新控制器以页面作为 QObject 父对象，页面卸载时不会留下浮动窗口或回调。
    DetailLayoutHost* host = new DetailLayoutHost(tableView, detailEditor, ownerWidget);
    detailHosts().append(QPointer<DetailLayoutHost>(host));
    host->applyScheme(currentDetailScheme());
    return host;
}

void ks::ui::DetailLayoutRegistry::applyGlobalScheme(
    const ks::settings::DetailDisplayScheme scheme)
{
    currentDetailScheme() = scheme;
    pruneDestroyedHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : detailHosts())
    {
        if (!hostPointer.isNull())
        {
            hostPointer->applyScheme(scheme);
        }
    }
}

ks::settings::DetailDisplayScheme ks::ui::DetailLayoutRegistry::globalScheme()
{
    return currentDetailScheme();
}

ks::ui::DetailLayoutHost* ks::ui::DetailLayoutRegistry::hostFor(
    CodeEditorWidget* detailEditor)
{
    if (detailEditor == nullptr)
    {
        return nullptr;
    }

    pruneDestroyedHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : detailHosts())
    {
        if (!hostPointer.isNull() && hostPointer->detailEditor() == detailEditor)
        {
            return hostPointer.data();
        }
    }
    return nullptr;
}

void ks::ui::DetailLayoutRegistry::prepareDataRebuild(CodeEditorWidget* detailEditor)
{
    DetailLayoutHost* host = hostFor(detailEditor);
    if (host != nullptr)
    {
        host->prepareDataRebuild();
    }
}
