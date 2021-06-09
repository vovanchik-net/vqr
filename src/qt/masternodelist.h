#ifndef BITCOIN_QT_MASTERNODELIST_H
#define BITCOIN_QT_MASTERNODELIST_H

#include <primitives/transaction.h>
#include <sync.h>
#include <util.h>

#include <QMenu>
#include <QTimer>
#include <QWidget>

#define MASTERNODELIST_UPDATE_SECONDS 3
#define MASTERNODELIST_FILTER_COOLDOWN_SECONDS 3

namespace Ui {
    class MasternodeList;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Masternode Manager page widget */
class MasternodeList : public QWidget {
    Q_OBJECT

public:
    explicit MasternodeList(QWidget* parent = 0);
    ~MasternodeList();

    enum {
        COLUMN_SERVICE,
        COLUMN_STATUS,
        COLUMN_LASTSEEN,
        COLUMN_LASTPAID,
        COLUMN_PAYOUT_ADDRESS,
        COLUMN_OUTPOINT,
    };

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);

private:
    QMenu* contextMenu;
    int64_t nTimeFilterUpdated;
    int64_t nTimeUpdated;
    int nTick;
    bool fFilterUpdated;

    QTimer* timer;
    Ui::MasternodeList* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;

    CCriticalSection cs_list;

    QString strCurrentFilter;

    bool mnListChanged;

    COutPoint GetSelectedMN();

    void updateList();

Q_SIGNALS:
    void doubleClicked(const QModelIndex&);

private Q_SLOTS:
    void showContextMenu(const QPoint&);
    void on_filterLineEdit_textChanged(const QString& strFilterIn);

    void extraInfo_clicked();
    void copyProTxHash_clicked();
    void copyCollateralOutpoint_clicked();

    void handleMasternodeListChanged();
    void updateListScheduled();
};
#endif // BITCOIN_QT_MASTERNODELIST_H
