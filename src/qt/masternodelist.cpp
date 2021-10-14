#include <qt/masternodelist.h>
#include <qt/forms/ui_masternodelist.h>

#include <qt/clientmodel.h>
#include <clientversion.h>
#include <coins.h>
#include <qt/guiutil.h>
#include <netbase.h>
#include <qt/walletmodel.h>

#include <univalue.h>
#include <key_io.h>
#include <utilstrencodings.h>

#include <QMessageBox>
#include <QTableWidgetItem>
#include <QtGui/QClipboard>
#include <masternode.h>
#include <interfaces/node.h>

int GetOffsetFromUtc() {
    return QDateTime::currentDateTime().offsetFromUtc();
}

MasternodeList::MasternodeList (QWidget* parent) : QWidget(parent), ui(new Ui::MasternodeList), clientModel(0), walletModel(0),
            fFilterUpdated(true), nTimeFilterUpdated(0), nTimeUpdated(0), mnListChanged(true), nTick(0) {
    ui->setupUi(this);

//    GUIUtil::setFont({ui->label_count_2, ui->countLabel}, GUIUtil::FontWeight::Bold, 14);
//    GUIUtil::setFont({ui->label_filter_2}, GUIUtil::FontWeight::Normal, 15);

    int columnAddressWidth = 120;
    int columnStatusWidth = 70;
    int columnLastSeenWidth = 100;
    int columnLastPaidWidth = 100;
    int columnPayeeWidth = 270;
    int columnOutpointWidth = 420;

//    ui->tableWidgetMasternodes->setColumnWidth(COLUMN_SERVICE, columnAddressWidth);
    ui->tableWidgetMasternodes->setColumnWidth(COLUMN_STATUS, columnStatusWidth);
    ui->tableWidgetMasternodes->setColumnWidth(COLUMN_LASTSEEN, columnLastSeenWidth);
    ui->tableWidgetMasternodes->setColumnWidth(COLUMN_LASTPAID, columnLastPaidWidth);
    ui->tableWidgetMasternodes->setColumnWidth(COLUMN_PAYOUT_ADDRESS, columnPayeeWidth);
    ui->tableWidgetMasternodes->setColumnWidth(COLUMN_OUTPOINT, columnOutpointWidth);
    ui->tableWidgetMasternodes->setContextMenuPolicy(Qt::CustomContextMenu);

    ui->filterLineEdit->setPlaceholderText(tr("Filter by any property (e.g. address or hash)"));

    QAction* copyProTxHashAction = new QAction(tr("Copy Outpoint Hash"), this);
    QAction* copyCollateralOutpointAction = new QAction(tr("Copy Collateral Outpoint"), this);
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyProTxHashAction);
    contextMenu->addAction(copyCollateralOutpointAction);
    connect(ui->tableWidgetMasternodes, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showContextMenu(const QPoint&)));
    connect(ui->tableWidgetMasternodes, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(extraInfo_clicked()));
    connect(copyProTxHashAction, SIGNAL(triggered()), this, SLOT(copyProTxHash_clicked()));
    connect(copyCollateralOutpointAction, SIGNAL(triggered()), this, SLOT(copyCollateralOutpoint_clicked()));

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateListScheduled()));
    timer->start(1000);

//    GUIUtil::updateFonts();
}

MasternodeList::~MasternodeList () {
    delete ui;
}

void MasternodeList::setClientModel (ClientModel* model) {
    this->clientModel = model;
    if (model) {
        connect(clientModel, SIGNAL(masternodeListChanged()), this, SLOT(handleMasternodeListChanged()));
    }
}

void MasternodeList::setWalletModel (WalletModel* model) {
    this->walletModel = model;
}

void MasternodeList::showContextMenu (const QPoint& point) {
    QTableWidgetItem* item = ui->tableWidgetMasternodes->itemAt(point);
    if (item) contextMenu->exec(QCursor::pos());
}

void MasternodeList::handleMasternodeListChanged () {
    LOCK(cs_list);
    mnListChanged = true;
}

void MasternodeList::updateListScheduled () {
    TRY_LOCK(cs_list, fLockAcquired);
    if (!fLockAcquired) return;

    if (!clientModel || clientModel->node().shutdownRequested()) {
        return;
    }

    if (fFilterUpdated) {
        int64_t nSecondsToWait = nTimeFilterUpdated - GetTime() + MASTERNODELIST_FILTER_COOLDOWN_SECONDS;
        ui->countLabel->setText(tr("Please wait...") + " " + QString::number(nSecondsToWait));

        if (nSecondsToWait <= 0) {
            updateList();
            fFilterUpdated = false;
        }
    } else if (mnListChanged) {
        int64_t nMnListUpdateSecods = masternodeSync.IsBlockchainSynced() ? MASTERNODELIST_UPDATE_SECONDS : MASTERNODELIST_UPDATE_SECONDS * 10;
        int64_t nSecondsToWait = nTimeUpdated - GetTime() + nMnListUpdateSecods;

        if (nSecondsToWait <= 0) {
            updateList();
            mnListChanged = false;
        }
    } else {
        nTick++;
        if (nTick < 0) nTick = -nTick;
        if (nTick > 60) updateList();
    }
}

void MasternodeList::updateList () {
    if (!clientModel || clientModel->node().shutdownRequested()) return;

    LOCK (cs_list);

    QString strToFilter;
    ui->countLabel->setText(tr("Updating..."));
    ui->tableWidgetMasternodes->setSortingEnabled(false);
    ui->tableWidgetMasternodes->clearContents();
    ui->tableWidgetMasternodes->setRowCount(0);

    nTimeUpdated = GetTime();
    nTick = 0;

    std::map<COutPoint, CMasternode> mnmaps = mnodeman.GetFullMasternodeMap();
    for (auto it : mnmaps) {
        QTableWidgetItem* addressItem = new QTableWidgetItem (QString::fromStdString (it.second.addr.ToString()));
        QTableWidgetItem* statusItem = new QTableWidgetItem (QString::fromStdString (it.second.GetStateString()));
        QTableWidgetItem* lastSeenItem = new QTableWidgetItem(QString::fromStdString(EasyFormatDateTime(it.second.lastPing.sigTime)));
        QTableWidgetItem* lastPaidItem = new QTableWidgetItem(QString::fromStdString(EasyFormatDateTime(it.second.nTimeLastPaid)));     
        QTableWidgetItem* payeeItem = new QTableWidgetItem(QString::fromStdString(EncodeDestination(
            it.second.pubKeyCollateralAddress.GetID())));
        QTableWidgetItem* outpointItem = new QTableWidgetItem (QString::fromStdString (
            it.first.hash.ToString() + ":" + itostr(it.first.n)));

        if (strCurrentFilter != "") {
            strToFilter = addressItem->text() + " " +
                          statusItem->text() + " " +
                          lastSeenItem->text() + " " +
                          lastPaidItem->text() + " " +
                          payeeItem->text() + " " +
                          outpointItem->text();
            if (!strToFilter.contains(strCurrentFilter)) return;
        }

        ui->tableWidgetMasternodes->insertRow(0);
//        ui->tableWidgetMasternodes->setItem(0, COLUMN_SERVICE, addressItem);
        ui->tableWidgetMasternodes->setItem(0, COLUMN_STATUS, statusItem);
        ui->tableWidgetMasternodes->setItem(0, COLUMN_LASTSEEN, lastSeenItem);
        ui->tableWidgetMasternodes->setItem(0, COLUMN_LASTPAID, lastPaidItem);
        ui->tableWidgetMasternodes->setItem(0, COLUMN_PAYOUT_ADDRESS, payeeItem);
        ui->tableWidgetMasternodes->setItem(0, COLUMN_OUTPOINT, outpointItem);
    };
    ui->countLabel->setText(QString::number(ui->tableWidgetMasternodes->rowCount ()));
    ui->tableWidgetMasternodes->setSortingEnabled (true);
}

void MasternodeList::on_filterLineEdit_textChanged (const QString& strFilterIn) {
    strCurrentFilter = strFilterIn;
    nTimeFilterUpdated = GetTime();
    fFilterUpdated = true;
    ui->countLabel->setText(tr("Please wait...") + " " + QString::number(MASTERNODELIST_FILTER_COOLDOWN_SECONDS));
}

COutPoint MasternodeList::GetSelectedMN () {
    if (!clientModel) return COutPoint();

    std::string strOutpoint;
    {
        LOCK(cs_list);
        QItemSelectionModel* selectionModel = ui->tableWidgetMasternodes->selectionModel();
        QModelIndexList selected = selectionModel->selectedRows();
        if (selected.count() == 0) return COutPoint();
        QModelIndex index = selected.at(0);
        int nSelectedRow = index.row();
        strOutpoint = ui->tableWidgetMasternodes->item(nSelectedRow, COLUMN_OUTPOINT)->text().toStdString();
    }
    
    size_t colon = strOutpoint.find_last_of(':');
    uint256 mnTxHash;
    uint32_t outputIndex = 0;
    if (colon != strOutpoint.npos) {
        mnTxHash.SetHex(strOutpoint.substr(0, colon));
        outputIndex = (uint32_t)atoi(strOutpoint.substr(colon + 1));
    } else {
        mnTxHash.SetHex(strOutpoint);
    }
    return COutPoint (mnTxHash, outputIndex);
}

void MasternodeList::extraInfo_clicked () {
    COutPoint dmn = GetSelectedMN();
    if (dmn.IsNull()) return;
    CMasternode mn;
    if (!mnodeman.Get(dmn, mn)) return;

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("service", mn.addr.ToString());
    obj.pushKV("nPoSeBanScore", mn.nPoSeBanScore);
    obj.pushKV("nPoSeBanHeight", mn.nPoSeBanHeight);
    obj.pushKV("sigTime", mn.sigTime);
    QString strWindowtitle = tr("Additional information for Masternode %1").arg(QString::fromStdString(mn.outpoint.hash.ToString()));
    QString strText = QString::fromStdString(obj.write());

    QMessageBox::information(this, strWindowtitle, strText);
}

void MasternodeList::copyProTxHash_clicked () {
    COutPoint dmn = GetSelectedMN();
    if (dmn.IsNull()) return;
    CMasternode mn;
    if (!mnodeman.Get(dmn, mn)) return;
    QApplication::clipboard()->setText(QString::fromStdString(mn.outpoint.hash.ToString()));
}

void MasternodeList::copyCollateralOutpoint_clicked () {
    COutPoint dmn = GetSelectedMN();
    if (dmn.IsNull()) return;
    QApplication::clipboard()->setText(QString::fromStdString(dmn.ToString()));
}
