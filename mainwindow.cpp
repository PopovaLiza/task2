#include "mainwindow.h"
#include "ui_mainwindow.h"

// Конструктор объекта формы
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    generator = std::mt19937(rd());
    rnd_distrib = std::uniform_real_distribution<double>(0.0, 1.0);
}

// деструктор объекта формы
MainWindow::~MainWindow()
{
    delete ui;
}

//Возвращает длину ключа в символах по его требуемой длине в битах
size_t MainWindow::get_key_size()
{
    return (ui->sb_key_length->value() * log10(2) + 1);
}

// реализация функции a^b % c
BigInt MainWindow::modular_pow(BigInt base, BigInt exponent, const BigInt &modulus)
{
    BigInt result = 1;
    base %= modulus;

    while (exponent > 0)
    {
        if (exponent % 2 == 1)
        {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }

    return result;
}

// нок
BigInt MainWindow::lcm(const BigInt &a, const BigInt &b)
{
    return abs(a * b);
}

// расщиренный алгоритм евклида
std::vector<BigInt> MainWindow::extended_gcd(BigInt a, BigInt b)
{
    BigInt x(0), old_x(1);
    BigInt y(1), old_y(0);

    while (b != 0)
    {
        auto quotient = a / b;
        BigInt temp_a = a;
        a = b;
        b = temp_a - quotient * b;

        BigInt temp_old_x = old_x;
        old_x = x;
        x = temp_old_x - quotient * x;

        BigInt temp_old_y = old_y;
        old_y = y;
        y = temp_old_y - quotient * y;
    }

    return {a, old_x, old_y};
}

// получение случайного большого числа в пределах minNum и maxNum
BigInt MainWindow::big_rand_range(int minNum, const BigInt &maxNum)
{
    return (maxNum - minNum) * (int) (100 * rnd_distrib(generator)) / 100 + minNum;
}

// начальный способ подтвердить простоту числа
BigInt MainWindow::simple_prime()
{
    while (true)
    {
        auto prime_num = BigInt::big_random(generator, get_key_size());
        for (auto f_prime : first_primes)
        {
            if (prime_num % f_prime == 0 && f_prime * f_prime <= prime_num)
            {
                break;
            }

            return prime_num;
        }
    }
}

// проверка простоты числа по методу миллера-рабина
bool MainWindow::miller_rabin_primality(const BigInt &mrc)
{
    int max_divisions_by_two = 0;
    BigInt ec = mrc - 1;
    while (ec % 2 == 0)
    {
        ec /= 2;
        max_divisions_by_two += 1;
    }

    auto miller_trial = [this, ec, mrc, max_divisions_by_two](const BigInt &round_tester)
    {
        if (modular_pow(round_tester, ec, mrc) == 1)
        {
            return false;
        }

        for (BigInt i = 0; i < max_divisions_by_two; i++)
        {
            if (modular_pow(round_tester, pow(BigInt(2), i.to_int()) * ec, mrc) == mrc - 1)
            {
                return false;
            }
        }

        return true;
    };

    for (unsigned int i = 0; i < MILLER_RABIN_TRIALS_AMOUNT; i++)
    {
        auto round_tester = big_rand_range(2, mrc);
        if (miller_trial(round_tester))
        {
            return false;
        }
    }

    return true;
}

// функция получения случайного большого простого числа
BigInt MainWindow::get_random_prime()
{
    while (true)
    {
        auto possible_prime = simple_prime();
        if (!miller_rabin_primality(possible_prime))
        {
            continue;
        }

        return possible_prime;
    }
}

// функция подбора e
BigInt MainWindow::choose_e(const BigInt &lcmv)
{
    while (true)
    {
        auto e = big_rand_range(3, BIGGEST_E);
        if (e < lcmv && gcd(e, lcmv) == 1)
        {
            return e;
        }
    }
}

// функция шифрования сообщения
std::vector<BigInt> MainWindow::encrypt(const std::string &message, const BigInt &exponent, const BigInt &modulus)
{
    std::vector<BigInt> result;
    result.reserve(message.size());

    for (char c : message)
    {
        auto encrypted_char = modular_pow(c, exponent, modulus);
        result.push_back(encrypted_char);
    }

    return result;
}

// функция расшифрования байтов в строку
std::string MainWindow::decrypt(const std::vector<BigInt> &encrypted, const BigInt &pkey, const BigInt &modulus)
{
    std::string result;

    for (const auto &byte : encrypted)
    {
        auto decrypted_char = modular_pow(byte, pkey, modulus);
        result += char(decrypted_char.to_int());
    }

    return result;
}

// функция нажатия на кнопку генерации ключей
void MainWindow::on_pb_generate_keys_clicked()
{
    auto P = get_random_prime();
    auto Q = get_random_prime();

    auto n = P * Q;
    auto lcm_v = lcm(P - 1, Q - 1);
    auto e = choose_e(lcm_v);

    auto ext_gcd_res = extended_gcd(e, lcm_v);
    auto d = ext_gcd_res[1];
    if (ext_gcd_res[1] < 0) {
        d += lcm_v;
    }

    ui->le_d->setText(d.to_string().c_str());
    ui->le_n->setText(n.to_string().c_str());
    ui->le_e->setText(e.to_string().c_str());
}

// функция нажатия на кнопку чтения ключей с диска
void MainWindow::on_pb_read_keys_clicked()
{
    QFile pub("keys.pub");
    QFile priv("keys.priv");
    if (!pub.exists()) {
        QMessageBox::information(this, "Информация", "Файл открытого ключа не найден");
        return;
    }
    if (!priv.exists()) {
        QMessageBox::information(this, "Информация", "Файл закрытого ключа не найден");
        return;
    }

    pub.open(QFile::ReadOnly);
    priv.open(QFile::ReadOnly);

    QTextStream pub_qts(&pub);
    QTextStream priv_qts(&priv);

    QString _e, _n, _d;

    pub_qts >> _e >> _n;
    priv_qts >> _d >> _n;

    ui->le_d->setText(_d);
    ui->le_n->setText(_n);
    ui->le_e->setText(_e);

    pub.close();
    priv.close();
}

// функция сохранения ключей на диск
void MainWindow::on_pb_save_keys_clicked()
{
    QFile pub("keys.pub");
    QFile priv("keys.priv");
    if (pub.exists()) {
        pub.remove();
    }
    if (priv.exists()) {
        priv.remove();
    }

    pub.open(QFile::WriteOnly | QFile::Truncate);
    priv.open(QFile::WriteOnly | QFile::Truncate);

    QTextStream pub_qts(&pub);
    QTextStream priv_qts(&priv);

    pub_qts << ui->le_e->text() << '\n' << ui->le_n->text();
    priv_qts << ui->le_d->text() << '\n' << ui->le_n->text();

    pub.close();
    priv.close();
}

// функция нажатия на кнопку дешифрования
void MainWindow::on_pb_encrypt_clicked()
{
    if (ui->le_d->text().isEmpty() || ui->le_n->text().isEmpty()) {
        QMessageBox::information(this, "Информация", "Для шифрования нужны e и n");
        return;
    }

    BigInt  e(ui->le_e->text().toStdString()),
            n(ui->le_n->text().toStdString());

    auto message = ui->pte_text->toPlainText().toStdString();
    auto enc_data = encrypt(message, e, n);
    QString encrypted_message;
    foreach(auto _be, enc_data) {
        encrypted_message.append(' ').append(_be.to_string().c_str());
    }
    ui->pte_cyphertext->setPlainText(encrypted_message.trimmed());
}

// функция нажатия на кнопку шифрования
void MainWindow::on_pb_decrypt_clicked()
{
    if (ui->le_d->text().isEmpty() || ui->le_n->text().isEmpty()) {
        QMessageBox::information(this, "Информация", "Для дешифрования нужны d и n");
        return;
    }

    BigInt  d(ui->le_d->text().toStdString()),
            n(ui->le_n->text().toStdString());

    std::vector<BigInt> encrypted_message;
    foreach (auto _be, ui->pte_cyphertext->toPlainText().split(" ")) {
        encrypted_message.emplace_back(_be.toStdString());
    }
    auto decrypted_message = decrypt(encrypted_message, d, n);
    ui->pte_text->setPlainText(QString::fromStdString(decrypted_message));
}
