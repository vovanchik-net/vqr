// Copyright (c) 2012-2019 The Peercoin developers
// Copyright (c) 2021 Uladzimir (t.me/crypto_dev)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <qt/coinsview.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <qt/csvmodelwriter.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>

#include <key_io.h>
#include <timedata.h>
#include <interfaces/handler.h>

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPoint>
#include <QScrollBar>
#include <QTableView>
#include <QVBoxLayout>
#include <QColor>
#include <QTimer>

class CoinsRec {
public:
    CoinsRec() : hash(), nTime(0), address(""), nValue(0), idx(0), spent(false), coinAge(0) { }

    CoinsRec(uint256 hash, int64_t nTime, const std::string &address, int64_t nValue, int idx, bool spent, 
            int64_t coinAge) : hash(hash), nTime(nTime), address(address), nValue(nValue), idx(idx), 
            spent(spent), coinAge(coinAge) { }

    uint256 hash;
    int64_t nTime;
    std::string address;
    int64_t nValue;
    int idx;
    bool spent;
    int64_t coinAge;
}; 

// Amount column is right-aligned it contains numbers
static int column_alignments[] = {
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignRight|Qt::AlignVCenter,
    Qt::AlignRight|Qt::AlignVCenter,
    Qt::AlignRight|Qt::AlignVCenter,
    Qt::AlignRight|Qt::AlignVCenter
};

struct TransactionNotification2 {
public:
    TransactionNotification2() {}
    TransactionNotification2(uint256 _hash, ChangeType _status) : hash(_hash), status(_status) {}

    void invoke(QObject *ttm) {
        QString strHash = QString::fromStdString(hash.GetHex());
        QMetaObject::invokeMethod(ttm, "updateTransaction", Qt::QueuedConnection,
                    Q_ARG(QString, strHash), Q_ARG(int, status));
    }
private:
    uint256 hash;
    ChangeType status;
};

static void NotifyTransactionChanged(CoinsTableModel *ttm, const uint256 &hash, ChangeType status) {
//    TransactionNotification2 notification(hash, status);
//    notification.invoke(ttm);
}

CoinsTableModel::CoinsTableModel(WalletModel *parent) : QAbstractTableModel(parent), walletModel(parent) {
    columns << tr("Transaction") << tr("Index") <<  tr("Address") << tr("Balance") << tr("Age") << tr("CoinDay");
    refreshWallet();
    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateAge()));
    timer->start(1000);
    connect(walletModel->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    m_handler_transaction_changed = walletModel->wallet().handleTransactionChanged(
        boost::bind(NotifyTransactionChanged, this, _1, _2)); 
}

CoinsTableModel::~CoinsTableModel() {
    m_handler_transaction_changed->disconnect();
}

void CoinsTableModel::setCoinsProxyModel(CoinsFilterProxy *coinsProxy) {
    coinsProxyModel = coinsProxy;
}

int CoinsTableModel::rowCount(const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return coinList.size();
}

int CoinsTableModel::columnCount(const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return columns.length();
}

QVariant CoinsTableModel::data(const QModelIndex &index, int role) const {
    const Consensus::Params& params = Params().GetConsensus();
    if (!index.isValid()) return QVariant();
    CoinsRec rec;
    if (index.row() >= 0 && index.row() < coinList.size()) {
        rec = static_cast<CoinsRec>(coinList[index.row()]);
    }
    if (rec.nTime == 0) return QVariant();
    switch(role) {
        case Qt::DisplayRole:
            switch(index.column()) {
                case TxHash:    return QString::fromStdString(rec.hash.ToString());
                case TxIndex:   return QString::number(rec.idx);
                case Address:   return QString::fromStdString(rec.address);
                case Balance:   return BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), rec.nValue);
                case Age:       return QString::number(int64_t((GetAdjustedTime() - rec.nTime) / 86400));
                case CoinDay:   return QString::number(rec.coinAge);
            }
            break;
        case Qt::TextAlignmentRole:
            return column_alignments[index.column()];
        case Qt::EditRole:
            switch (index.column()) {
                case TxHash:    return QString::fromStdString(rec.hash.ToString());
                case TxIndex:   return QString::number(rec.idx);
                case Address:   return QString::fromStdString(rec.address);
                case Balance:   return qint64(rec.nValue);
                case Age:       return qint64((GetAdjustedTime() - rec.nTime) / 86400);
                case CoinDay:   return qint64(rec.coinAge);
            }
            break;
        case Qt::BackgroundColorRole:
            int minAge = 3 * params.nCoinAgeTick / 60 / 60 / 24;
            int maxAge = 255 * params.nCoinAgeTick / 60 / 60 / 24;
            int Age = (GetAdjustedTime() - rec.nTime) / 86400;
            if (Age < minAge) {
                return COLOR_MINT_YOUNG;
            } else if (Age >= minAge && Age < maxAge) {
                return COLOR_MINT_MATURE;
            } else {
                return COLOR_MINT_OLD;
            }
            break;
    }
    return QVariant();
}

QVariant CoinsTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation == Qt::Horizontal) {
        if(role == Qt::DisplayRole) {
            return columns[section];
        } else if (role == Qt::TextAlignmentRole) {
            return column_alignments[section];
        } else if (role == Qt::ToolTipRole) {
            switch (section) {
                case Address:           return tr("Destination address of the output.");
                case TxHash:            return tr("Original transaction id.");
                case TxIndex:           return tr("Original transaction id index.");
                case Age:               return tr("Age of the transaction in days.");
                case Balance:           return tr("Balance of the output.");
                case CoinDay:           return tr("Coin age in the output.");
            }
        }
    }
    return QVariant();
}

QModelIndex CoinsTableModel::index(int row, int column, const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return createIndex(row, column, row);
}

void CoinsTableModel::refreshWallet() {
    interfaces::Wallet& wallet = walletModel->wallet();
    QList<CoinsRec> tempList;
    for (const auto& wtx : wallet.getWalletTxs()) {
        uint256 hash = wtx.tx->GetHash();
        std::vector<CoinsRec> txList;
        interfaces::WalletTxStatus tx_status;
        int num_blocks;
        int64_t adjusted_time;
        if (wallet.tryGetTxStatus (wtx.tx->GetHash(), tx_status, num_blocks, adjusted_time) &&
                    (!tx_status.is_abandoned)/* && (tx_status.depth_in_main_chain > 0)*/) {
            const Consensus::Params& params = Params().GetConsensus();
            int nDayWeight = (std::min((GetAdjustedTime() - wtx.time), params.nCoinAgeTick*255) - params.nCoinAgeTick*3) / 86400;
            for (size_t nOut = 0; nOut < wtx.tx->vout.size(); nOut++) {
                CTxOut txOut = wtx.tx->vout[nOut];
                if (!wallet.txoutIsMine(txOut)) continue;
                uint64_t coinAge = std::max(txOut.nValue * nDayWeight / COIN, (int64_t)0);
                CTxDestination address;
                std::string addrStr;
                if (ExtractDestination(txOut.scriptPubKey, address)) {
                    addrStr = EncodeDestination(address);
                }
                txList.push_back(CoinsRec(hash, wtx.time, addrStr, txOut.nValue, nOut, 
                    wallet.txoutIsSpent(hash, nOut), coinAge));
            }
        }
        for (const CoinsRec& kr : txList)
            if (!kr.spent)
                tempList.append(kr);
    }
    beginResetModel();
    coinList = tempList;
    endResetModel();
}

void CoinsTableModel::updateTransaction(const QString &hash, int status) {
    refreshWallet();
    coinsProxyModel->invalidate();
}

void CoinsTableModel::updateAge() {
    Q_EMIT dataChanged(index(0, Age), index(coinList.size()-1, Age));
    Q_EMIT dataChanged(index(0, CoinDay), index(coinList.size()-1, CoinDay));
}

void CoinsTableModel::updateDisplayUnit() {
    Q_EMIT dataChanged(index(0, Balance), index(coinList.size()-1, Balance));
}

CoinsView::CoinsView(QWidget *parent) : QWidget(parent), model(0), coinsView(0) {
    QHBoxLayout *hlayout = new QHBoxLayout();
    hlayout->setContentsMargins(0,0,0,0);

    QString legendBoxStyle = "background-color: rgb(%1,%2,%3); border: 1px solid black;";

    QLabel *youngColor = new QLabel(" ");
    youngColor->setMaximumHeight(15);
    youngColor->setMaximumWidth(10);
    youngColor->setStyleSheet(legendBoxStyle.arg(COLOR_MINT_YOUNG.red()).arg(COLOR_MINT_YOUNG.green()).arg(COLOR_MINT_YOUNG.blue()));
    QLabel *youngLegend = new QLabel(tr("transaction is too young"));
    youngLegend->setContentsMargins(5,0,15,0);

    QLabel *matureColor = new QLabel(" ");
    matureColor->setMaximumHeight(15);
    matureColor->setMaximumWidth(10);
    matureColor->setStyleSheet(legendBoxStyle.arg(COLOR_MINT_MATURE.red()).arg(COLOR_MINT_MATURE.green()).arg(COLOR_MINT_MATURE.blue()));
    QLabel *matureLegend = new QLabel(tr("transaction is mature"));
    matureLegend->setContentsMargins(5,0,15,0);

    QLabel *oldColor = new QLabel(" ");
    oldColor->setMaximumHeight(15);
    oldColor->setMaximumWidth(10);
    oldColor->setStyleSheet(legendBoxStyle.arg(COLOR_MINT_OLD.red()).arg(COLOR_MINT_OLD.green()).arg(COLOR_MINT_OLD.blue()));
    QLabel *oldLegend = new QLabel(tr("transaction has reached maximum probability"));
    oldLegend->setContentsMargins(5,0,15,0);

    QHBoxLayout *legendLayout = new QHBoxLayout();
    legendLayout->setContentsMargins(10,10,0,0);
    legendLayout->addWidget(youngColor);
    legendLayout->addWidget(youngLegend);
    legendLayout->addWidget(matureColor);
    legendLayout->addWidget(matureLegend);
    legendLayout->addWidget(oldColor);
    legendLayout->addWidget(oldLegend);
    legendLayout->insertStretch(-1);

    hlayout->insertStretch(0);

    QVBoxLayout *vlayout = new QVBoxLayout(this);
    vlayout->setContentsMargins(0,0,0,0);
    vlayout->setSpacing(0);

    QTableView *view = new QTableView(this);
    vlayout->addLayout(hlayout);
    vlayout->addWidget(view);
    vlayout->addLayout(legendLayout);

    vlayout->setSpacing(0);
    int width = view->verticalScrollBar()->sizeHint().width();
    // Cover scroll bar width with spacing
#ifdef Q_WS_MAC
    hlayout->addSpacing(width+2);
#else
    hlayout->addSpacing(width);
#endif
    // Always show scroll bar
    view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    view->setTabKeyNavigation(false);
    view->setContextMenuPolicy(Qt::CustomContextMenu);

    coinsView = view;

    QAction *copyAddressAction = new QAction(tr("Copy address"), this);
    QAction *copyTransactionIdAction = new QAction(tr("Copy transaction id"), this);
    QAction *doRefreshAction = new QAction(tr("Refresh"), this);

    contextMenu =new QMenu();
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyTransactionIdAction);
    contextMenu->addAction(doRefreshAction);

    connect(view, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(copyAddress()));
    connect(copyTransactionIdAction, SIGNAL(triggered()), this, SLOT(copyTransactionId()));
    connect(doRefreshAction, SIGNAL(triggered()), this, SLOT(doRefresh()));
}

void CoinsView::setModel(WalletModel *model) {
    this->model = model;
    if (model) {
        coinsProxyModel = new CoinsFilterProxy(this);
        coinsProxyModel->setSourceModel(model->getCoinsTableModel());
        coinsProxyModel->setDynamicSortFilter(true);
        coinsProxyModel->setSortRole(Qt::EditRole);
        model->getCoinsTableModel()->setCoinsProxyModel(coinsProxyModel);

        coinsView->setModel(coinsProxyModel);
        coinsView->setAlternatingRowColors(true);
        coinsView->setSelectionBehavior(QAbstractItemView::SelectRows);
        coinsView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        coinsView->setSortingEnabled(true);
        coinsView->sortByColumn(CoinsTableModel::CoinDay, Qt::DescendingOrder);
        coinsView->verticalHeader()->hide();

        coinsView->horizontalHeader()->resizeSection(CoinsTableModel::Address, 320);
        coinsView->horizontalHeader()->setSectionResizeMode(CoinsTableModel::TxHash, QHeaderView::Stretch);
        coinsView->horizontalHeader()->resizeSection(CoinsTableModel::TxIndex, 60);
        coinsView->horizontalHeader()->resizeSection(CoinsTableModel::Age, 60);
        coinsView->horizontalHeader()->resizeSection(CoinsTableModel::Balance, 100);
        coinsView->horizontalHeader()->resizeSection(CoinsTableModel::CoinDay,100);
    }
}

void CoinsView::exportClicked() {
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Minting Data"), QString(),
            tr("Comma separated file (*.csv)"), nullptr);

    if (filename.isNull()) return;
    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(coinsProxyModel);
    writer.addColumn(tr("Address"), CoinsTableModel::Address);
    writer.addColumn(tr("Transaction"), CoinsTableModel::TxHash);
    writer.addColumn(tr("Transaction Index"), CoinsTableModel::TxIndex);
    writer.addColumn(tr("Age"), CoinsTableModel::Age);
    writer.addColumn(tr("CoinDay"), CoinsTableModel::CoinDay);
    writer.addColumn(tr("Balance"), CoinsTableModel::Balance);

    if (!writer.write()) {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}

void CoinsView::contextualMenu(const QPoint &point) {
    QModelIndex index = coinsView->indexAt(point);
    if (index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void CoinsView::copyAddress() {
    GUIUtil::copyEntryData(coinsView, CoinsTableModel::Address, Qt::DisplayRole);
}

void CoinsView::copyTransactionId() {
    GUIUtil::copyEntryData(coinsView, CoinsTableModel::TxHash, Qt::DisplayRole);
}

void CoinsView::doRefresh() {
    model->getCoinsTableModel()->refreshWallet();
    coinsProxyModel->invalidate();
}
